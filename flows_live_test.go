package main

import (
	"os"
	"runtime"
	"testing"
)

// Explicit opt-in: reads the real conntrack table; never changes routes/services.
func TestFlowLiveSnapshot(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("VPNGUARD_TEST_FLOW_READ") != "1" {
		t.Skip("requires explicit read-only Linux conntrack test")
	}
	setup(t)
	oldS, oldSim := S, Sim
	defer func() { S = oldS; Sim = oldSim }()
	S, Sim = realSys{}, false
	m := &flowModule{}
	if err := m.Set("flows.enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if m.at.IsZero() || m.Status().State != "Снимок соединений" {
		t.Fatal("real collector failed", m.Status())
	}
	if len(m.rows) > 512 {
		t.Fatal("unbounded snapshot")
	}
	for _, row := range m.Tables()[0].Rows {
		if row[5] != "Unknown" {
			t.Fatal("unsupported classification")
		}
	}
	if err := m.Set("flows.enabled", "false"); err != nil {
		t.Fatal(err)
	}
	if len(m.rows) != 0 || !m.at.IsZero() {
		t.Fatal("disable retained addresses")
	}
}
