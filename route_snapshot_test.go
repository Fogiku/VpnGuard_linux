package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOwnedRulesExcludeVendorAndCustomRules(t *testing.T) {
	for _, line := range []string{"1101: from all fwmark 0x11 lookup 101", "1201: from all fwmark 0x40000000/0x40000000 lookup main", "1201: from all fwmark 0x40000000/0x40000000 lookup 254"} {
		if _, ok := ownedRule(line); !ok {
			t.Fatalf("owned rule missed: %s", line)
		}
	}
	for _, line := range []string{"28814: from all fwmark 0x4d555052 lookup 52807", "1101: from 192.168.1.0/24 fwmark 0x11 lookup 101", "100: from all fwmark 0x11 lookup 101", "1101: from all fwmark 0x11 lookup 999", "0: from all lookup local"} {
		if _, ok := ownedRule(line); ok {
			t.Fatalf("foreign rule selected: %s", line)
		}
	}
}

type transactionSys struct {
	Sys
	fail     string
	commands []string
	inputs   []string
}

func (s *transactionSys) Run(d time.Duration, in, name string, args ...string) (string, int) {
	c := name + " " + strings.Join(args, " ")
	s.commands = append(s.commands, c)
	s.inputs = append(s.inputs, in)
	if c == s.fail {
		s.fail = ""
		return "injected failure", 1
	}
	switch c {
	case "nft list tables":
		return "table inet vpnguard\n", 0
	case "nft list table inet vpnguard":
		return "table inet vpnguard { chain original {} }\n", 0
	case "ip -4 -N -o rule show":
		return "1101: from all fwmark 0x11 lookup 101\n28814: from all fwmark 0x4d555052 lookup 52807\n", 0
	case "ip -4 -N -o route show table all":
		return "default dev old0 table 101 scope link\n", 0
	}
	return s.Sys.Run(d, in, name, args...)
}

func transactionSetup(t *testing.T) *transactionSys {
	t.Helper()
	setup(t)
	applied, appliedIP = "", ""
	previousState = nil
	routeApplyDeferred = false
	s := &transactionSys{Sys: S}
	S = s
	return s
}

func TestRouteFailureRestoresKernelAndModel(t *testing.T) {
	s := transactionSetup(t)
	if err := saveJSON("routes.json", rt); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(DataDir + "/routes.json")
	n := defaultRoutes()
	n.Profiles[0].Name = "candidate"
	n.Profiles[0].Rules[len(n.Profiles[0].Rules)-1].Exit = "direct"
	s.fail = "ip rule add fwmark 0x11 lookup 101 priority 1101"
	if err := setRoutes(n); err == nil {
		t.Fatal("injected failure accepted")
	}
	after, _ := os.ReadFile(DataDir + "/routes.json")
	if string(before) != string(after) || rt.Profiles[0].Name == "candidate" {
		t.Fatal("failed update changed saved/model routes")
	}
	commands := strings.Join(s.commands, "\n")
	if !strings.Contains(commands, "ip -4 rule add priority 1101 from all fwmark 0x11 lookup 101") {
		t.Fatal("kernel rule not restored")
	}
	if strings.Contains(commands, "route flush table 101") {
		t.Fatal("unchanged default route was disturbed")
	}
	if !strings.Contains(strings.Join(s.inputs, "\n"), "chain original") {
		t.Fatal("original nft missing")
	}
	if strings.Contains(commands, "rule del priority 28814") {
		t.Fatal("vendor rules touched")
	}
}

func TestRoutePreflightFailureDoesNotMutateKernel(t *testing.T) {
	s := transactionSetup(t)
	s.fail = "nft -c -f -"
	if err := Apply("invalid"); err == nil {
		t.Fatal("preflight failure ignored")
	}
	if len(s.commands) != 1 {
		t.Fatalf("mutation after preflight error: %v", s.commands)
	}
}

func TestRouteRollbackRestoresModelAndDisk(t *testing.T) {
	transactionSetup(t)
	if err := Apply("baseline"); err != nil {
		t.Fatal(err)
	}
	n := defaultRoutes()
	n.Profiles[0].Rules = []Rule{{ID: "all", Exit: "direct", Last: true}}
	if err := setRoutes(n); err != nil {
		t.Fatal(err)
	}
	if pending := pendingRouteView(); pending != nil {
		if err := confirmRouteChange(pending.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := Rollback(); err != nil {
		t.Fatal(err)
	}
	if rt.Profiles[0].Rules[0].Exit != "zapret" {
		t.Fatal("model not restored")
	}
	var saved Routes
	if !loadJSON("routes.json", &saved) || saved.Profiles[0].Rules[0].Exit != "zapret" {
		t.Fatal("saved routes not restored")
	}
}

func TestRouteSaveFailureRestoresKernelAndModel(t *testing.T) {
	s := transactionSetup(t)
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	DataDir = blocked
	n := defaultRoutes()
	n.Profiles[0].Rules = []Rule{{ID: "all", Exit: "direct", Last: true}}
	if err := setRoutes(n); err == nil {
		t.Fatal("save failure ignored")
	}
	if rt.Profiles[0].Rules[0].Exit != "zapret" || applied != "" {
		t.Fatal("model/bookkeeping changed on failed save")
	}
	for _, cmd := range s.commands {
		if cmd == "nft -f -" || strings.HasPrefix(cmd, "ip rule add") {
			t.Fatal("kernel mutated despite unavailable journal storage")
		}
	}
}

// Запускается только в отдельном Linux network namespace с правами root.
func TestRouteSnapshotIsolatedKernel(t *testing.T) {
	if os.Getenv("VPNGUARD_NETNS_TEST") != "1" {
		t.Skip("requires an isolated network namespace")
	}
	S = realSys{}
	for _, cmd := range [][]string{
		{"ip", "link", "add", "old0", "type", "dummy"}, {"ip", "link", "set", "old0", "up"},
		{"ip", "route", "add", "default", "dev", "old0", "table", "101"},
		{"ip", "rule", "add", "priority", "1101", "fwmark", "0x11", "lookup", "101"},
		{"ip", "rule", "add", "priority", "28814", "fwmark", "0x4d555052", "lookup", "52807"},
	} {
		if out, c := run(cmd[0], cmd[1:]...); c != 0 {
			t.Fatalf("%v: %s", cmd, out)
		}
	}
	if out, c := S.Run(time.Second, "table inet vpnguard {\n chain original {\n }\n}\n", "nft", "-f", "-"); c != 0 {
		t.Fatal(out)
	}
	s, err := snapshotRoutes()
	if err != nil {
		t.Fatal(err)
	}
	run("ip", "route", "replace", "default", "dev", "lo", "table", "101")
	run("ip", "rule", "del", "priority", "1101")
	if out, c := S.Run(time.Second, "delete table inet vpnguard\ntable inet vpnguard {\n chain candidate {\n }\n}\n", "nft", "-f", "-"); c != 0 {
		t.Fatal(out)
	}
	if err := s.restore(); err != nil {
		t.Fatal(err)
	}
	routes, _ := run("ip", "route", "show", "table", "101")
	rules, _ := run("ip", "rule", "show")
	nft, _ := run("nft", "list", "table", "inet", "vpnguard")
	if !strings.Contains(routes, "old0") || !strings.Contains(rules, "1101:") || !strings.Contains(rules, "28814:") || !strings.Contains(nft, "original") || strings.Contains(nft, "candidate") {
		t.Fatalf("restoration mismatch: %s\n%s\n%s", routes, rules, nft)
	}
}
