package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPassiveDPIWireGuardSample(t *testing.T) {
	if os.Getenv("VPNGUARD_TEST_PASSIVE_DPI") != "1" {
		t.Skip("requires ndpiReader 4.2.0 and a disposable Linux network namespace")
	}
	oldS, oldSim := S, Sim
	S, Sim = realSys{}, false
	defer func() { S, Sim = oldS, oldSim }()
	client := kernelNamespace(t)
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	configure := func(iface string, port int, own, peer *ecdh.PrivateKey, allowed, endpoint string) {
		kernelCommand(t, "ip", "link", "add", iface, "type", "wireguard")
		cfg := fmt.Sprintf("[Interface]\nListenPort=%d\nPrivateKey=%s\n[Peer]\nPublicKey=%s\nAllowedIPs=%s/32\n%s", port, base64.StdEncoding.EncodeToString(own.Bytes()), base64.StdEncoding.EncodeToString(peer.PublicKey().Bytes()), allowed, endpoint)
		if _, code := S.Run(3*time.Second, cfg, "wg", "setconf", iface, "/proc/self/fd/0"); code != 0 {
			t.Fatal("test WireGuard configuration failed")
		}
	}
	configure("wg_server", 41001, serverKey, clientKey, "10.99.0.2", "")
	configure("wg_peer", 41002, clientKey, serverKey, "10.99.0.1", "Endpoint=127.0.0.1:41001\n")
	kernelCommand(t, "ip", "link", "set", "wg_peer", "netns", client)
	kernelCommand(t, "ip", "addr", "add", "10.99.0.1/24", "dev", "wg_server")
	kernelCommand(t, "ip", "link", "set", "wg_server", "up")
	for _, args := range [][]string{{"ip", "addr", "add", "10.99.0.2/24", "dev", "wg_peer"}, {"ip", "link", "set", "wg_peer", "up"}} {
		kernelCommand(t, append([]string{"nsenter", "-t", client, "-n"}, args...)...)
	}
	const rule = "table inet dpi_test { chain input { type filter hook input priority filter; ct state new counter; }\n}\n"
	if out, code := S.Run(3*time.Second, rule, "nft", "-f", "-"); code != 0 {
		t.Fatal(out)
	}
	events := startFlowEvents(realSys{})
	defer events.stop()
	waitEventReady(t, events)
	_, ready := kernelPython(t, client, `import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
print("ready",flush=True)
for _ in range(400):
    s.sendto(bytes.fromhex("000101000001000000000000076578616d706c6504746573740000010001"),("10.99.0.1",53))
    time.sleep(.05)
`)
	if ready() != "ready" {
		t.Fatal("client failed")
	}
	deadline := time.Now().Add(6 * time.Second)
	for {
		b, err := events.dpiBoundary()
		ready := false
		for _, l := range b.Frame.Rows {
			if l.Row.DestinationPort == 53 {
				ready = true
			}
		}
		if err == nil && ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DNS NEW not observed")
		}
		time.Sleep(50 * time.Millisecond)
	}
	oldCfg := cfgMap
	cfgMap = map[string]string{"flows.enabled": "true", "flows.eventsEnabled": "true", "flows.dpiEnabled": "true"}
	defer func() { cfgMap = oldCfg }()
	m := &flowModule{events: events}
	m.Tick()
	if len(m.bindings) != 1 || m.dpi == nil || len(m.dpi.Rows) != 1 || m.dpi.Rows[0][0] != "DNS" {
		t.Fatalf("unexpected sample: %+v, bindings %d", m.dpi, len(m.bindings))
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, row := range m.Tables()[0].Rows {
			if row[1] == "udp" && row[3] == "10.99.0.1:53" && row[5] == "DNS" {
				t.Log("WG conntrack row", row)
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("confirmed DNS generation missing from connection table", m.Tables()[0])
}

type sampleTestSys struct {
	flowTestSys
	dpiOutput string
	probes    int
}

func (s *sampleTestSys) Run(d time.Duration, in, name string, args ...string) (string, int) {
	if in == passiveDPIScript && name == "python3" && len(args) == 2 && args[0] == "-" && args[1] == wgMod.iface() {
		s.probes++
		return s.dpiOutput, 0
	}
	return s.flowTestSys.Run(d, in, name, args...)
}

func TestPassiveDPISettingsAndExpiredResult(t *testing.T) {
	setup(t)
	oldS, oldSim := S, Sim
	defer func() { S, Sim = oldS, oldSim }()
	data, err := json.Marshal(map[string]any{"start": 1700000000000, "end": 1700000002000, "packets": 1, "csv": dpiCSVHeader + dpiCSVRow})
	if err != nil {
		t.Fatal(err)
	}
	s := &sampleTestSys{flowTestSys: flowTestSys{Sys: S, output: `{"rows":[]}`}, dpiOutput: string(data)}
	S, Sim = s, false
	m := &flowModule{}
	if err := m.Set("flows.enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if s.probes != 0 {
		t.Fatal("unexpected capture")
	}
	if err := m.Set("flows.dpiEnabled", "true"); err != nil {
		t.Fatal(err)
	}
	tables := m.Tables()
	if len(tables) != 2 || len(tables[1].Rows) != 1 || tables[1].Rows[0][0] != "HTTP" {
		t.Fatal(tables)
	}
	s.dpiOutput = `{"error":"missing"}`
	m.Tick()
	if tab := m.Tables()[1]; len(tab.Rows) != 0 || !strings.Contains(tab.Empty, "libndpi-bin") {
		t.Fatal(tab)
	}
	if err := m.Set("flows.dpiEnabled", "false"); err != nil {
		t.Fatal(err)
	}
	if s.probes != 2 || len(m.Tables()) != 1 {
		t.Fatal("capture still active")
	}
}
