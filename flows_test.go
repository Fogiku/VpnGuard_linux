package main

import (
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
	s.code = 1
	m.Tick()
	if len(m.rows) != 0 || !m.at.IsZero() || m.Status().Level != 1 {
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
