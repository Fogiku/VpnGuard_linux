package main

import (
	"strings"
	"testing"
	"time"
)

type flowTestSys struct {
	Sys
	output string
	code   int
	calls  int
}

func (s *flowTestSys) Run(d time.Duration, in, name string, args ...string) (string, int) {
	s.calls++
	if name != "python3" || len(args) != 1 || args[0] != "-" || in != flowSnapshotScript || d != 3*time.Second {
		panic("unexpected flow command")
	}
	return s.output, s.code
}
func TestFlowObserverClearsFailedAndDisabledSnapshots(t *testing.T) {
	setup(t)
	oldS, oldSim := S, Sim
	defer func() { S = oldS; Sim = oldSim }()
	s := &flowTestSys{Sys: S, output: `{"rows":[{"protocol":"udp","source":"192.168.15.2","destination":"1.1.1.1","sourcePort":12345,"destinationPort":443,"mark":65536}],"seen":1,"truncated":false}`}
	S = s
	Sim = false
	m := &flowModule{}
	m.Tick()
	if s.calls != 0 {
		t.Fatal("disabled collector ran")
	}
	if err := m.Set("flows.enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if len(m.rows) != 1 || m.Tables()[0].Rows[0][5] != "Unknown" {
		t.Fatal("snapshot or unknown classification lost")
	}
	if counts := m.snapshotCounts(); counts == nil || counts.UDP != 1 || counts.TCP != 0 || counts.Truncated {
		t.Fatalf("wrong collector totals: %+v", counts)
	}
	s.code = 1
	m.Tick()
	if m.snapshotCounts() != nil || len(m.rows) != 0 || !m.at.IsZero() || m.Status().Level != 1 {
		t.Fatal("failed collector retained stale snapshot")
	}
	if err := m.Set("flows.enabled", "false"); err != nil {
		t.Fatal(err)
	}
	calls := s.calls
	m.Tick()
	if s.calls != calls {
		t.Fatal("disabled collector kept running")
	}
}

func TestRemoteFlowCounts(t *testing.T) {
	setup(t)
	token := newToken()
	setCfg("remote.token", token)
	setCfg("remote.enabled", "true")
	setCfg("remote.until", time.Now().Add(time.Hour).Format(time.RFC3339))
	old := flowsMod
	flowsMod = &flowModule{}
	t.Cleanup(func() { flowsMod = old })
	check := func(want string) {
		t.Helper()
		code, body := remoteGet("/v1/diagnostics/flows", token, "127.0.0.1")
		if code != 200 || strings.TrimSpace(body) != want {
			t.Fatalf("status %d, body %s", code, body)
		}
	}
	check(`{"schemaVersion":1,"snapshot":null}`)
	flowsMod.at = time.Unix(123, 0)
	check(`{"schemaVersion":1,"snapshot":{"at":123,"tcp":0,"udp":0,"truncated":false}}`)
	flowsMod.rows = []flowRow{{Protocol: "udp", Source: "private"}, {Protocol: "tcp", Destination: "private"}, {Protocol: "udp"}}
	flowsMod.truncated = true
	check(`{"schemaVersion":1,"snapshot":{"at":123,"tcp":1,"udp":2,"truncated":true}}`)
}

func TestFlowPinByteLabel(t *testing.T) {
	resources := legacyRouteResources()
	for mark, want := range map[uint32]string{
		0xab1100ff: "meduza", 0x1411: "—", 0x00fe0000: "0xfe",
	} {
		if got := flowPinLabel(mark, resources); got != want {
			t.Errorf("mark %#x: got %q, want %q", mark, got, want)
		}
	}
}
