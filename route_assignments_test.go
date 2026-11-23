package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type assignmentSys struct {
	occupiedRouteSys
	t       *testing.T
	owner   string
	checked bool
}

func (s *assignmentSys) Run(d time.Duration, in, name string, args ...string) (string, int) {
	if name == "ip" && strings.HasPrefix(strings.Join(args, " "), "route replace default dev wg1") {
		saved, exists, err := loadRouteAssignments()
		if err != nil || !exists || saved[len(saved)-1].Owner != s.owner {
			s.t.Fatalf("kernel mutation before saving assignments: %v, %v", saved, err)
		}
		pending, err := readRouteChange(routePendingFile)
		if err != nil || !pending.KernelChanged || pending.Before.resources[len(pending.Before.resources)-1].Owner != s.owner {
			s.t.Fatalf("new owner missing from rollback checkpoint: %v", err)
		}
		s.checked = true
	}
	return s.occupiedRouteSys.Run(d, in, name, args...)
}

func TestWireGuardExitAllocationLifecycle(t *testing.T) {
	tx := transactionSetup(t)
	baseMods := append([]Module(nil), Mods...)
	defer func() { Mods = baseMods }()
	s := &assignmentSys{occupiedRouteSys: occupiedRouteSys{tx,
		"1103: from all fwmark 0x20 lookup 103\n7: from all fwmark 0x20/0xf0 lookup 104\n1106: from all lookup 201",
		"default dev foreign table 105"}, t: t, owner: "wg-out-wg1"}
	S = s
	exits, err := configuredTunnelExits("wg1", "")
	if err != nil {
		t.Fatal(err)
	}
	Register(exits[0])
	exits[0].Tick()
	if !exits[0].Status().Up {
		t.Fatal(exits[0].Status())
	}
	if _, err := currentRouteResources(); err == nil {
		t.Fatal("read silently allocated a new owner")
	}
	if _, err := os.Stat(filepath.Join(DataDir, assignmentFile)); !os.IsNotExist(err) {
		t.Fatal("preview wrote a reservation", err)
	}
	setCfg("net.pinFlows", "true")
	rt.Profiles[0].Rules = []Rule{{ID: "vpn", Exit: s.owner, Last: true}}
	if err := Apply("new wireguard"); err != nil {
		t.Fatal(err)
	}
	if !s.checked {
		t.Fatal("normal routing entry point did not apply")
	}
	commands := strings.Join(tx.commands, "\n")
	prepare := strings.Index(commands, "ip rule add fwmark 0x30 lookup 107 priority 1107")
	if prepare < 0 || strings.Index(commands, "nft -f -") <= prepare {
		t.Fatal("nft published a mark before the new exit was ready")
	}
	want := routeResource{s.owner, 0x30, 0xffffffff, "107", 1107}
	entries, err := currentRouteResources()
	if err != nil || entries[len(entries)-1] != want {
		t.Fatal(entries, err)
	}
	if !strings.Contains(applied, "meta mark set 0x30") || !strings.Contains(appliedIP, `["route","replace","default","dev","wg1","table","107"]`) {
		t.Fatal("compiled rules did not use the saved pair")
	}
	regBytes, _ := os.ReadFile(filepath.Join(DataDir, assignmentFile))
	// Restart with different kernel occupancy. A saved owner is never renumbered.
	S = occupiedRouteSys{tx, "1107: from all lookup 222", ""}
	appliedIP, applied = "", ""
	if err := Apply("restart with conflict"); err == nil {
		t.Fatal("reassigned or overwrote a conflicting resource")
	}
	got, _ := os.ReadFile(filepath.Join(DataDir, assignmentFile))
	if string(got) != string(regBytes) {
		t.Fatal("conflict changed the assignments")
	}
	// Temporarily remove the instance and register another one.
	Mods = append([]Module(nil), baseMods...)
	two := &tunnelExit{iface: "wg2"}
	Register(two)
	S = occupiedRouteSys{tx, "", ""}
	two.Tick()
	if err := Apply("new owner"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(applied, `meta mark 0x30 counter drop comment "pinned exit removed"`) {
		t.Fatal("orphaned flows can escape")
	}
	entries, err = currentRouteResources()
	if err != nil || len(entries) != 7 || entries[6].Mark == want.Mark || entries[6].Table == want.Table {
		t.Fatal(entries, err)
	}
	Register(&tunnelExit{iface: "wg1"})
	entries, err = currentRouteResources()
	if err != nil || entries[6] != want {
		t.Fatal("returning owner changed", entries, err)
	}
}

func TestRouteAssignmentMigrationAndBadState(t *testing.T) {
	tx := transactionSetup(t)
	baseMods := Mods
	defer func() { Mods = baseMods }()
	m := &tunnelExit{iface: "wg5"}
	entries := append(legacyRouteResources(), routeResource{m.ID(), 0x72, 0xffffffff, "133", 1133})
	if err := saveJSON(routeLastFile, routeChange{ID: "legacy", Before: &routeSnapshot{resources: entries}}); err != nil {
		t.Fatal(err)
	}
	Register(m)
	if err := Apply("adopt legacy"); err != nil {
		t.Fatal(err)
	}
	saved, exists, err := loadRouteAssignments()
	if !exists || err != nil || saved[6] != entries[6] {
		t.Fatal(saved, err)
	}
	tx.commands = nil
	if err := saveFile(assignmentFile, []byte("null")); err != nil {
		t.Fatal(err)
	}
	if err := Apply("invalid ledger"); err == nil || len(tx.commands) != 0 {
		t.Fatal("bad ledger did not stop before kernel access", err, tx.commands)
	}
}

func TestVPNResourceExhaustion(t *testing.T) {
	used, err := occupiedVPNs(legacyRouteResources(), "1: from all fwmark 0/0 lookup 254", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := used.allocate("new"); err == nil {
		t.Fatal("allocated from a fully masked range")
	}
	used, err = occupiedVPNs(legacyRouteResources(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 96; i++ {
		r, err := used.allocate("new")
		if err != nil || r.Priority == 1198 {
			t.Fatal(r, err)
		}
	}
	if _, err := used.allocate("new"); err == nil {
		t.Fatal("allocated from a full table range")
	}
}

func TestConcurrentVPNAssignments(t *testing.T) {
	if dir := os.Getenv("VPNGUARD_ASSIGNMENTS_DIR"); dir != "" {
		DataDir, Sim, S = dir, true, newSim()
		Mods = []Module{&tunnelExit{iface: os.Getenv("VPNGUARD_ASSIGNMENTS_IFACE")}}
		err := routeOperation("concurrent registration", false, false, func() error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if runtime.GOOS != "linux" {
		t.Skip("uses Linux route file lock")
	}
	dir := t.TempDir()
	var workers []*exec.Cmd
	for _, iface := range []string{"wg1", "wg2"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestConcurrentVPNAssignments$")
		cmd.Env = append(os.Environ(), "VPNGUARD_ASSIGNMENTS_DIR="+dir, "VPNGUARD_ASSIGNMENTS_IFACE="+iface)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		workers = append(workers, cmd)
	}
	for _, cmd := range workers {
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, assignmentFile))
	var saved []routeResource
	if err != nil || json.Unmarshal(b, &saved) != nil || len(saved) != 8 || validateRouteResources(saved) != nil {
		t.Fatal("concurrent reservations lost", string(b), err)
	}
}

// Fail after the default route is installed and before nft can publish its mark.
type rejectVPNSelector struct{ Sys }

func (s rejectVPNSelector) Run(d time.Duration, input, name string, args ...string) (string, int) {
	if name == "ip" && strings.Join(args, " ") == "rule add fwmark 0x21 lookup 104 priority 1104" {
		return "injected selector failure", 1
	}
	return s.Sys.Run(d, input, name, args...)
}

func TestVPNAssignmentIsolatedKernel(t *testing.T) {
	if os.Getenv("VPNGUARD_NETNS_TEST") != "1" {
		t.Skip("requires isolated Linux namespace")
	}
	oldS, oldMods, oldData, oldSim, oldCfg := S, Mods, DataDir, Sim, cfgMap
	defer func() { S, Mods, DataDir, Sim, cfgMap = oldS, oldMods, oldData, oldSim, oldCfg }()
	S, Sim, DataDir, cfgMap = realSys{}, true, t.TempDir(), map[string]string{"net.wan": "wan0", "net.pinFlows": "true", "dns.enabled": "false"}
	out := &tunnelExit{iface: "wg1"}
	Mods = []Module{&flowTestExit{id: "direct", iface: "wan0", mark: 0x14}, &flowTestExit{id: "block", mark: 0x1f}, out}
	rt = defaultRoutes()
	rt.Profiles[0].Rules = []Rule{{ID: "all", Exit: out.ID(), Last: true}}
	applied, appliedIP = "", ""
	kernelCommand(t, "ip", "link", "add", "wan0", "type", "dummy")
	kernelCommand(t, "ip", "link", "set", "wan0", "up")
	kernelCommand(t, "ip", "link", "add", "wg1", "type", "wireguard")
	kernelCommand(t, "ip", "link", "set", "wg1", "up")
	kernelCommand(t, "ip", "rule", "add", "pref", "1103", "fwmark", "0x20", "lookup", "103")
	kernelCommand(t, "ip", "route", "add", "default", "dev", "wan0", "table", "103")
	out.setSt(0, true, "up", "")
	S = rejectVPNSelector{realSys{}}
	if err := Apply("partial kernel failure"); err == nil {
		t.Fatal("injected rule failure ignored")
	}
	partial, _ := run("ip", "-4", "-N", "-o", "route", "show", "table", "all")
	if strings.Contains(partial, "table 104") || !strings.Contains(partial, "default dev wan0 table 103") || hasRoutePending() {
		t.Fatal("partial application was not rolled back", partial)
	}
	saved, exists, err := loadRouteAssignments()
	if err != nil || !exists || saved[len(saved)-1].Table != "104" {
		t.Fatal("reservation lost on rollback", err)
	}
	S = realSys{}
	if err := Apply("kernel allocation"); err != nil {
		t.Fatal(err)
	}
	rules, _ := run("ip", "-4", "-N", "-o", "rule", "show")
	routes, _ := run("ip", "-4", "-N", "-o", "route", "show", "table", "all")
	if !strings.Contains(rules, "fwmark 0x21 lookup 104") || !strings.Contains(rules, "fwmark 0x20 lookup 103") || !strings.Contains(routes, "default dev wg1 table 104") || !strings.Contains(routes, "default dev wan0 table 103") {
		t.Fatalf("unexpected kernel state: %s %s", rules, routes)
	}
	if err := previousState.restore(); err != nil {
		t.Fatal(err)
	}
	rules, _ = run("ip", "-4", "-N", "-o", "rule", "show")
	routes, _ = run("ip", "-4", "-N", "-o", "route", "show", "table", "all")
	if strings.Contains(rules, "lookup 104") || strings.Contains(routes, "table 104") || !strings.Contains(rules, "fwmark 0x20 lookup 103") || !strings.Contains(routes, "default dev wan0 table 103") {
		t.Fatalf("rollback damaged ownership: %s %s", rules, routes)
	}
}

func TestConfiguredWireGuardExits(t *testing.T) {
	setup(t)
	m := mod("inet")
	if err := m.Set("vpn.extraWireGuard", "wg1, wg2"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"wg1,wg1", "wg_server", "awg0", "wg1,", "lo", "-interface", "../bad"} {
		if err := m.Set("vpn.extraWireGuard", bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if cfg("vpn.extraWireGuard", "") != "wg1,wg2" {
		t.Fatal("rejected setting changed saved interfaces")
	}
}

func TestOlcRTCExit(t *testing.T) {
	tx := transactionSetup(t)
	orig := append([]Module(nil), Mods...)
	t.Cleanup(func() { Mods = orig })
	settings := mod("inet")
	if olcVisible(inboundOlc) {
		t.Fatal("olcRTC should be hidden by default")
	}
	if err := settings.Set("modules.olc", "true"); err != nil {
		t.Fatal(err)
	}
	if !olcVisible(inboundOlc) {
		t.Fatal("olcRTC should be enabled")
	}

	if err := settings.Set("vpn.extraWireGuard", "wg1"); err != nil {
		t.Fatal(err)
	}
	if err := settings.Set("vpn.olcRTC", " olc0 "); err != nil {
		t.Fatal(err)
	}
	for _, conflict := range [][2]string{{"vpn.olcRTC", "wg1"}, {"vpn.extraWireGuard", "olc0"}, {"vpn.olcRTC", "olc0,olc0"}, {"vpn.olcRTC", "../tun"}} {
		if settings.Set(conflict[0], conflict[1]) == nil {
			t.Fatal("accepted collision or invalid name", conflict)
		}
	}
	exits, err := configuredTunnelExits(cfg("vpn.extraWireGuard", ""), cfg("vpn.olcRTC", ""))
	if err != nil || len(exits) != 2 || exits[0].ID() != "wg-out-wg1" || exits[1].ID() != "olcrtc-out-olc0" {
		t.Fatal(exits, err)
	}
	exit := exits[1]
	Register(exit)
	exit.Tick()
	if !exit.Status().Up || !exit.Exit().TCPOnly {
		t.Fatal(exit.Status())
	}
	rt.Profiles[0].Rules = []Rule{{ID: "olc", Exit: exit.ID(), Last: true}}
	if err := Apply("olcRTC"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(appliedIP, `"default","dev","olc0"`) || !strings.Contains(applied, "meta l4proto != tcp counter drop") {
		t.Fatal(applied, appliedIP)
	}
	for _, target := range currentQualityTargets() {
		if target.Iface == "olc0" {
			t.Fatal("scheduled ICMP over TCP proxy")
		}
	}
	if err := tx.WriteFile("/sys/class/net/olc0/tun_flags", "0x1002", 0600); err != nil {
		t.Fatal(err)
	}
	exit.Tick()
	if exit.Status().Up {
		t.Fatal("accepted TAP in place of TUN")
	}
}
