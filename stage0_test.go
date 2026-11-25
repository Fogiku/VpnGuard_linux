package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestStageZeroGatewayReplay(t *testing.T) {
	raw, err := os.ReadFile("testdata/stage0.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			ID, Fault string
			Expected  struct{ Control, Application bool } `json:"expected_gateway"`
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 3 {
		t.Fatal("expected three stage 0 scenarios")
	}
	for _, c := range fixture.Cases {
		t.Run(c.ID, func(t *testing.T) {
			sim := newSim()
			old := S
			S = sim
			t.Cleanup(func() { S = old })
			if err := sim.WriteFile(zArgs, "--lua-desync=multisplit", 0600); err != nil {
				t.Fatal(err)
			}
			if _, code := run("systemctl", "start", zUnit); code != 0 {
				t.Fatal("simulation setup failed")
			}
			if c.Fault != "" {
				sim.SetFault(c.Fault, true)
			}
			control := probe("eth0", "https://control.example.test")
			service := probe("eth0", "https://youtube.example.test")
			if control != c.Expected.Control || service != c.Expected.Application {
				t.Fatalf("control=%v service=%v", control, service)
			}
		})
	}
}
