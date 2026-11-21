package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyRouteStartupRecoveryIsolatedKernel(t *testing.T) {
	if os.Getenv("VPNGUARD_NETNS_TEST") != "1" {
		t.Skip("requires isolated Linux network namespace")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Readlink("/proc/1/ns/net")
	if err != nil || self == host {
		t.Fatal("requires a separate network namespace", err)
	}
	oldSys, oldDir, oldSim := S, DataDir, Sim
	t.Cleanup(func() { S, DataDir, Sim = oldSys, oldDir, oldSim })
	S, DataDir, Sim = realSys{}, t.TempDir(), false
	for _, iface := range []string{"old0", "new0"} {
		kernelCommand(t, "ip", "link", "add", iface, "type", "dummy")
		kernelCommand(t, "ip", "link", "set", iface, "up")
	}
	kernelCommand(t, "ip", "route", "add", "default", "dev", "new0", "table", "101")
	kernelCommand(t, "ip", "rule", "add", "priority", "1102", "fwmark", "0x12", "lookup", "102")
	kernelCommand(t, "ip", "rule", "add", "priority", "2200", "fwmark", "0x44", "lookup", "200")
	kernelCommand(t, "ip", "route", "add", "default", "dev", "new0", "table", "200")
	fixture, err := os.ReadFile("testdata/legacy-routes-pending.json")
	if err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(DataDir, routePendingFile)
	if err := os.WriteFile(pending, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	for startup := 1; startup <= 2; startup++ {
		if err := recoverRoutesOnStartup(); err != nil {
			t.Fatalf("startup %d: %v", startup, err)
		}
		if _, err := os.Stat(pending); !os.IsNotExist(err) {
			t.Fatalf("startup %d: pending journal, stat error %v", startup, err)
		}
		rules, code := run("ip", "-4", "-N", "rule", "show")
		rules = strings.Join(strings.Fields(rules), " ")
		if code != 0 || strings.Count(rules, "1101: from all fwmark 0x11 lookup 101") != 1 ||
			strings.Contains(rules, "1102:") || strings.Count(rules, "2200: from all fwmark 0x44 lookup 200") != 1 {
			t.Fatalf("startup %d: unexpected rules: %s", startup, rules)
		}
		for table, iface := range map[string]string{"101": "old0", "200": "new0"} {
			out, code := run("ip", "-4", "route", "show", "table", table)
			if code != 0 || strings.TrimSpace(out) != "default dev "+iface+" scope link" {
				t.Fatalf("startup %d: table %s: %s", startup, table, out)
			}
		}
		kernelCommand(t, "nft", "list", "chain", "inet", "vpnguard", "original")
		events := routeHistory()
		if len(events) != 1 || events[0].ID != "17" || events[0].Status != "recovered" {
			t.Fatalf("startup %d: unexpected recovery history: %+v", startup, events)
		}
	}
}
