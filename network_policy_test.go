package main

import (
	"strings"
	"testing"
)

func TestLocalNetworkValidation(t *testing.T) {
	if got := ownedDefaults("default dev old0 table 101 scope link linkdown")["101"]; len(got) != 1 || strings.Contains(got[0], "linkdown") {
		t.Fatalf("kernel-only route flags retained: %v", got)
	}
	for _, value := range []string{"0.0.0.0/0", "::1/128", "example.com", "192.168.1.0/99"} {
		if _, err := parseLocalNetworks(value); err == nil {
			t.Fatalf("unsafe local bypass accepted: %s", value)
		}
	}
	got, err := parseLocalNetworks("192.168.1.44/24, 192.168.1.0/24\n192.168.100.0/24")
	if err != nil || strings.Join(got, ",") != "192.168.1.0/24,192.168.100.0/24" {
		t.Fatalf("canonical networks: %v %v", got, err)
	}
}

func TestNetworkPolicyRollbackRestoresSetting(t *testing.T) {
	transactionSetup(t)
	if err := setNetworkPolicy("net.pinFlows", "true"); err != nil {
		t.Fatal(err)
	}
	if !cfgBool("net.pinFlows", false) {
		t.Fatal("pinning not saved")
	}
	if pending := pendingRouteView(); pending != nil {
		if err := confirmRouteChange(pending.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := Rollback(); err != nil {
		t.Fatal(err)
	}
	if cfgBool("net.pinFlows", false) {
		t.Fatal("rollback left pinning enabled")
	}
	var saved map[string]string
	if !loadJSON("config.json", &saved) {
		t.Fatal("config unavailable")
	}
	if _, ok := saved["net.pinFlows"]; ok {
		t.Fatal("originally absent setting was not removed")
	}
}

func TestNetworkPolicyFailureRestoresSetting(t *testing.T) {
	s := transactionSetup(t)
	s.fail = "ip rule add fwmark 0x11 lookup 101 priority 1101"
	if err := setNetworkPolicy("net.localNetworks", "192.168.1.0/24"); err == nil {
		t.Fatal("ip failure accepted")
	}
	if cfg("net.localNetworks", "") != "" {
		t.Fatal("failed policy was saved")
	}
}
