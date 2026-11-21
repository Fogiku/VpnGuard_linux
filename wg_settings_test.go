package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWireGuardSubnetSaveFailure(t *testing.T) {
	sys := transactionSetup(t)
	oldSubnet := wgMod.subnet()
	ip := wgMod.d.Clients[0].IP
	rt.Clients[ip] = "p-test"
	rt.Overrides[ip] = []Rule{{ID: "local-rule"}}
	path := filepath.Join(DataDir, "config.json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	sys.commands = nil
	if err := wgMod.Set("wg.subnet", "10.77.5"); err == nil {
		t.Fatal("subnet change reported success despite failed config write")
	}
	if wgMod.subnet() != oldSubnet || wgMod.d.Clients[0].IP != ip ||
		rt.Clients[ip] != "p-test" || len(rt.Overrides[ip]) != 1 {
		t.Fatal("failed subnet change moved client or routing policy")
	}
	for _, cmd := range sys.commands {
		if cmd == "systemctl restart "+wgMod.unit() {
			t.Fatal("failed subnet change restarted WireGuard")
		}
	}
}
