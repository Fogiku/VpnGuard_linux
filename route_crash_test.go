package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type crashAfterRouteSys struct{ Sys }

func (s crashAfterRouteSys) Run(d time.Duration, input, name string, args ...string) (string, int) {
	out, code := s.Sys.Run(d, input, name, args...)
	if name == "ip" && strings.Join(args, " ") == "route replace default dev out1 table 101" && code == 0 {
		os.Exit(79)
	}
	return out, code
}

func TestRouteJournalCrashChild(t *testing.T) {
	directory := os.Getenv("VG_ROUTE_CRASH_CHILD")
	if directory == "" {
		t.Skip("helper process")
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if self == "" || self == host {
		t.Fatal("crash fixture must be isolated")
	}
	S, Sim, DataDir = crashAfterRouteSys{realSys{}}, true, directory
	cfgMap = map[string]string{}
	loadCfg()
	Mods = nil
	for _, m := range []*flowTestExit{{id: "direct", iface: "out0", mark: 0x14}, {id: "meduza", iface: "out1", mark: 0x11, table: 101}, {id: "block", mark: 0x1f}} {
		m.setSt(0, true, "up", "")
		Mods = append(Mods, m)
	}
	wgMod.d = wgData{Priv: "loaded", Clients: []*WgClient{{IP: "10.253.0.2"}}}
	loadRoutes()
	if err := setNetworkPolicy("net.pinFlows", "true"); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash injection was not reached")
}

func TestRouteJournalIndependentRecoveryIsolatedKernel(t *testing.T) {
	if os.Getenv("VPNGUARD_NETNS_TEST") != "1" {
		t.Skip("requires isolated Linux network namespace")
	}
	oldS, oldDir := S, DataDir
	t.Cleanup(func() { S, DataDir = oldS, oldDir })
	S, DataDir = realSys{}, t.TempDir()
	for _, iface := range []string{"old0", "out0", "out1"} {
		kernelCommand(t, "ip", "link", "add", iface, "type", "dummy")
		kernelCommand(t, "ip", "link", "set", iface, "up")
	}
	kernelCommand(t, "ip", "route", "add", "default", "dev", "old0", "table", "101")
	kernelCommand(t, "ip", "rule", "add", "priority", "1101", "fwmark", "0x11", "lookup", "101")
	kernelCommand(t, "ip", "rule", "add", "priority", "28814", "fwmark", "0x4d555052", "lookup", "52807")
	if out, code := S.Run(time.Second, "table inet vpnguard {\n chain original {\n }\n}\n", "nft", "-f", "-"); code != 0 {
		t.Fatal(out)
	}
	config := []byte(`{"net.pinFlows":"false","net.wan":"out0","unrelated":"keep"}`)
	if err := os.WriteFile(filepath.Join(DataDir, "config.json"), config, 0600); err != nil {
		t.Fatal(err)
	}
	model := Routes{Profiles: []Profile{{ID: "p1", Name: "original", Rules: []Rule{{ID: "all", Exit: "meduza", Last: true}}}}, Clients: map[string]string{}, Overrides: map[string][]Rule{}, Policy: map[string]ExitPolicy{}}
	raw, _ := json.Marshal(model)
	if err := os.WriteFile(filepath.Join(DataDir, "routes.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestRouteJournalCrashChild$")
	child.Env = append(os.Environ(), "VG_ROUTE_CRASH_CHILD="+DataDir)
	out, err := child.CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 79 {
		t.Fatalf("expected hard exit 79: %s %v", out, err)
	}
	change, err := readRouteChange(routePendingFile)
	if err != nil {
		t.Fatal(err)
	}
	if !change.KernelChanged {
		t.Fatal("crash journal lost the mutation flag")
	}
	current, _ := run("ip", "route", "show", "table", "101")
	if !strings.Contains(current, "out1") {
		t.Fatal("fixture did not mutate the route")
	}
	if err := os.WriteFile(filepath.Join(DataDir, "route-guard.py"), routeGuardSource, 0600); err != nil {
		t.Fatal(err)
	}
	unit := "vpnguard-route-proof-" + change.ID
	t.Cleanup(func() { run("systemctl", "stop", unit+".timer", unit+".service") })
	kernelCommand(t, "systemd-run", "--quiet", "--unit="+unit, "--on-active=2s", "--timer-property=AccuracySec=1s", "--property=NetworkNamespacePath=/proc/"+fmt.Sprint(os.Getpid())+"/ns/net", "/usr/bin/python3", filepath.Join(DataDir, "route-guard.py"), "isolated", DataDir, change.ID)
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(filepath.Join(DataDir, routePendingFile)); os.IsNotExist(err) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := os.Stat(filepath.Join(DataDir, routePendingFile)); !os.IsNotExist(err) {
		logs, _ := run("journalctl", "-u", unit+".service", "--no-pager", "-n", "12")
		t.Fatalf("independent recovery did not finish: %s", logs)
	}
	current, _ = run("ip", "route", "show", "table", "101")
	rules, _ := run("ip", "rule", "show")
	nft, _ := run("nft", "list", "table", "inet", "vpnguard")
	if !strings.Contains(current, "old0") || !strings.Contains(rules, "28814:") || strings.Contains(rules, "1200:") || !strings.Contains(nft, "original") {
		t.Fatalf("incomplete recovery: %s\n%s\n%s", current, rules, nft)
	}
	var restored map[string]string
	if !loadJSON("config.json", &restored) || restored["net.pinFlows"] != "false" || restored["unrelated"] != "keep" {
		t.Fatal("configuration not recovered")
	}
	file, _ := os.ReadFile(filepath.Join(DataDir, "routes.json"))
	if string(file) != string(raw) {
		t.Fatal("routes file not restored byte for byte")
	}
	events := routeHistory()
	if len(events) == 0 || events[len(events)-1].Status != "recovered" {
		t.Fatal("recovery event missing")
	}
}
