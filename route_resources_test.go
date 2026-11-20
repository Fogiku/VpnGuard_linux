package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRouteResourcesRejectCollisionsBeforeMutation(t *testing.T) {
	for _, extra := range []*flowTestExit{
		{id: "vpn2", mark: 0x11, table: 103},
		{id: "vpn2", mark: 0x20, table: 101},
		{id: "vpn2", mark: 0x20, table: 200},
		{id: "vpn2", mark: 0x100, table: 103},
		{id: "meduza", mark: 0x20, table: 103},
	} {
		t.Run(extra.id+string(rune(extra.mark)), func(t *testing.T) {
			s := transactionSetup(t)
			old := Mods
			defer func() { Mods = old }()
			Mods = append(append([]Module{}, Mods...), extra)
			if err := Apply("collision"); err == nil {
				t.Fatal("conflict accepted")
			}
			if len(s.commands) != 0 {
				t.Fatalf("kernel accessed despite conflict: %v", s.commands)
			}
		})
	}
}

func TestAdditionalVPNResourcePersistsAndPins(t *testing.T) {
	setup(t)
	old := Mods
	defer func() { Mods = old }()
	extra := &flowTestExit{id: "vpn2", iface: "vpn2if", mark: 0x20, table: 103}
	extra.setSt(0, true, "up", "")
	Mods = append(append([]Module{}, Mods...), extra)
	cfgMap["net.pinFlows"] = "true"
	resources, err := currentRouteResources()
	if err != nil {
		t.Fatal(err)
	}
	script, commands := Compile()
	if !strings.Contains(script, "0x00200000") {
		t.Fatal("new exit missing from flow restore")
	}
	raw, _ := json.Marshal(commands)
	if !strings.Contains(string(raw), `"103"`) || !strings.Contains(string(raw), `"1103"`) {
		t.Fatal("new exit missing from routing commands")
	}
	saved, _ := json.Marshal(routeSnapshot{resources: resources})
	var snapshot routeSnapshot
	if err := json.Unmarshal(saved, &snapshot); err != nil {
		t.Fatal(err)
	}
	if _, ok := resourceRule("1103: from all fwmark 0x20 lookup 103", snapshot.resources); !ok {
		t.Fatal("snapshot lost extra owner")
	}
	if _, ok := resourceRule("1103: from 192.168.1.0/24 fwmark 0x20 lookup 103", snapshot.resources); ok {
		t.Fatal("foreign selector claimed")
	}
	if _, ok := resourceRule("1104: from all fwmark 0x20 lookup 103", snapshot.resources); ok {
		t.Fatal("foreign priority claimed")
	}
	var legacy routeSnapshot
	if err := json.Unmarshal([]byte(`{"nft":"","rules":[],"defaults":{}}`), &legacy); err != nil || len(legacy.resources) != 6 {
		t.Fatal("legacy snapshot incompatible", err)
	}
	resources[6].Table = "52807"
	bad, _ := json.Marshal(routeSnapshot{resources: resources})
	if err := json.Unmarshal(bad, &snapshot); err == nil {
		t.Fatal("vendor table accepted")
	}
}

func TestAdditionalVPNRecoveryIsolatedKernel(t *testing.T) {
	if os.Getenv("VPNGUARD_NETNS_TEST") != "1" {
		t.Skip("requires isolated Linux namespace")
	}
	oldS, oldMods := S, Mods
	defer func() { S, Mods = oldS, oldMods }()
	S = realSys{}
	Mods = append(append([]Module{}, Mods...), &flowTestExit{id: "vpn2", mark: 0x20, table: 103})
	for _, iface := range []string{"old0", "new0"} {
		kernelCommand(t, "ip", "link", "add", iface, "type", "dummy")
		kernelCommand(t, "ip", "link", "set", iface, "up")
	}
	kernelCommand(t, "ip", "route", "add", "default", "dev", "old0", "table", "103")
	kernelCommand(t, "ip", "route", "add", "default", "dev", "old0", "table", "104")
	kernelCommand(t, "ip", "rule", "add", "priority", "1103", "fwmark", "0x20", "lookup", "103")
	kernelCommand(t, "ip", "rule", "add", "priority", "1104", "fwmark", "0x21", "lookup", "104")
	snapshot, err := snapshotRoutes()
	if err != nil {
		t.Fatal(err)
	}
	bytes, _ := json.Marshal(snapshot)
	var restored routeSnapshot
	if err := json.Unmarshal(bytes, &restored); err != nil {
		t.Fatal(err)
	}
	for _, python := range []bool{false, true} {
		kernelCommand(t, "ip", "route", "replace", "default", "dev", "new0", "table", "103")
		kernelCommand(t, "ip", "rule", "del", "priority", "1103")
		if python {
			path := filepath.Join(t.TempDir(), "snapshot.json")
			if err := os.WriteFile(path, bytes, 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("python3", "-c", "import sys,json; sys.path.insert(0,'deploy'); import route_guard; route_guard.restore_network(json.load(open(sys.argv[1])))", path)
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("Python recovery: %s %v", out, err)
			}
		} else if err := restored.restore(); err != nil {
			t.Fatal(err)
		}
		routes, _ := run("ip", "route", "show", "table", "103")
		foreign, _ := run("ip", "route", "show", "table", "104")
		rules, _ := run("ip", "rule", "show")
		if !strings.Contains(routes, "old0") || strings.Contains(routes, "new0") || !strings.Contains(foreign, "old0") || !strings.Contains(rules, "1103:") || !strings.Contains(rules, "1104:") {
			t.Fatalf("recovery lost own/foreign resources: %s %s %s", routes, foreign, rules)
		}
	}
}
