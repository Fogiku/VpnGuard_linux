package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
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
	server := httptest.NewUnstartedServer(nil)
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
from probe_client_path import measure
os.environ["PATH"] = %q + ":" + os.environ["PATH"]
os.environ["SSL_CERT_FILE"] = %q
resolve = socket.getaddrinfo
with patch("socket.getaddrinfo", side_effect=lambda name,*args: resolve("10.99.0.1" if name=="example.com" else name,*args)):
    print(json.dumps(measure("example.com","lab",False)),flush=True)
`, dir, cert))
	var result struct {
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
	t.Log(string(raw))
}
