package main

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// Run in a disposable gateway namespace with wg, nft, ip, nsenter and Python 3.
func TestWireGuardClientPolicy(t *testing.T) {
	if os.Getenv("VPNGUARD_TEST_WG_PATH") != "1" {
		t.Skip("requires disposable WireGuard gateway namespace")
	}
	oldS, oldSim, oldData, oldCfg, oldMods, oldWg, oldRt := S, Sim, DataDir, cfgMap, Mods, wgMod.d, rt
	t.Cleanup(func() {
		S, Sim, DataDir, cfgMap, Mods, wgMod.d, rt = oldS, oldSim, oldData, oldCfg, oldMods, oldWg, oldRt
	})
	S, Sim, DataDir = realSys{}, false, t.TempDir()
	cfgMap = map[string]string{"net.pinFlows": "true"}
	client := wireGuardTestPeer(t)
	direct := &flowTestExit{id: "direct", iface: "lo", mark: 0x14}
	direct.setSt(0, true, "up", "")
	Mods = []Module{direct, &flowTestExit{id: "block", mark: 0x1f}}
	wgMod.d = wgData{Priv: "loaded", Clients: []*WgClient{{IP: "10.99.0.2"}}}
	rt = Routes{Profiles: []Profile{{ID: "wg", Rules: []Rule{{ID: "default", Exit: "direct", Last: true}}}}}
	script, _ := Compile()
	marker := regexp.MustCompile("chain vg_policy_([a-f0-9]{64}) ").FindStringSubmatch(script)
	if len(marker) != 2 {
		t.Fatal("missing compiled policy marker")
	}
	if repeat, _ := Compile(); repeat != script {
		t.Fatal("unstable compiled policy")
	}
	cfgMap["net.pinFlows"] = "false"
	if changed, _ := Compile(); regexp.MustCompile(marker[1]).MatchString(changed) {
		t.Fatal("revision unchanged when disabling pinning")
	}
	cfgMap["net.pinFlows"] = "true"
	if out, code := S.Run(5*time.Second, script, "nft", "-f", "-"); code != 0 {
		t.Fatal(out)
	}
	// Minimal Discord Gateway fixture on the WG endpoint, sharing the HTTPS certificate.
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.NotFound(w, r)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(25 * time.Second))
		digest := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(digest[:]))
		message := []byte(`{"op":10,"d":{"heartbeat_interval":45000}}`)
		rw.Write([]byte{0x81, byte(len(message))})
		rw.Write(message)
		rw.Flush()
		// Keep the connection alive during the gateway observation; acknowledge Close.
		if _, err := rw.ReadByte(); err == nil {
			rw.Write([]byte{0x88, 0})
			rw.Flush()
		}
	}))
	server.Listener.Close()
	var err error
	server.Listener, err = net.Listen("tcp4", "10.99.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	defer server.Close()
	dir := t.TempDir()
	cert := filepath.Join(dir, "test-ca.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	// Stand in for SSH transport only. Execute the actual stdin helper in the gateway namespace.
	shim := fmt.Sprintf("#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n if [ \"$1\" = python3 ]; then exec nsenter -t %d -n \"$@\"; fi\n shift\ndone\nexit 1\n", os.Getpid())
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(shim), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nsenter", "-t", client, "-n", "python3", "-c", fmt.Sprintf(`import json, os, socket, sys
from unittest.mock import patch
sys.path.insert(0, "deploy")
from probe_client_path import measure, measure_discord
os.environ["PATH"] = %q + ":" + os.environ["PATH"]
os.environ["SSL_CERT_FILE"] = %q
resolve = socket.getaddrinfo
with patch("socket.getaddrinfo", side_effect=lambda name,*args: resolve("10.99.0.1" if name=="example.com" else name,*args)):
    result = measure("example.com","lab",False)
    if os.environ.get("VPNGUARD_TEST_DISCORD_PATH") == "1":
        result["discord"] = measure_discord("lab", False, host="example.com")
    print(json.dumps(result),flush=True)
`, dir, cert))
	var result struct {
		Discord struct {
			Gateway string `json:"discord_gateway"`
			Flow    struct{ PolicyRevision, PinnedExit, Correlation string }
		}
		TLS  bool
		HTTP int
		Flow struct{ PolicyRevision, PinnedExit, Correlation string }
	}
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("client probe: %v: %s", err, raw)
	}
	if err := json.Unmarshal(raw, &result); err != nil || !result.TLS || result.HTTP != 404 || result.Flow.PolicyRevision != marker[1] || result.Flow.PinnedExit != "direct" || result.Flow.Correlation != "pin_and_observed_policy" {
		t.Fatal(string(raw), err)
	}
	if os.Getenv("VPNGUARD_TEST_DISCORD_PATH") == "1" && (result.Discord.Gateway != "hello" || result.Discord.Flow != result.Flow) {
		t.Fatal(string(raw))
	}
	t.Log(string(raw))
}
