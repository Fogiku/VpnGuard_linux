package main

import (
	"strings"
	"testing"
	"time"
)

func TestZapretExtendedProbeResults(t *testing.T) {
	for _, tc := range []struct {
		out       string
		exit      int
		speed, ok bool
	}{
		{"200 1048576 1.0 0.1 0.2", 0, true, true},
		{"200 1048576 15 0.1 0.2", 0, true, false},
		{"200 4000 0.01 0.01 0.01", 0, true, false},
		{"403 1048576 1.0 0.1 0.2", 0, true, false},
		{"200 4194304 18 0.1 0.2", 28, true, true},
		{"000 0 12 0 0", 28, false, false},
		{"204 0 0.1 0.01 0.05", 0, false, true},
	} {
		if r := parseZProbe(tc.out, tc.exit, tc.speed); r.OK != tc.ok {
			t.Errorf("%+v: %+v", tc, r)
		}
	}
}
func TestZapretExtendedTargets(t *testing.T) {
	setup(t)
	setCfg("zapret.targets", zapretLegacyTargets)
	m := mod("zapret").(*zapret2)
	targets := strings.Join(m.targets(), ",")
	for _, want := range []string{"gateway.discord.gg", "cdn.discordapp.com", "redirector.googlevideo.com", "ytvideo", "ytspeed"} {
		if !strings.Contains(targets, want) {
			t.Errorf("missing %s", want)
		}
	}
	setCfg("zapret.videoCheck", "false")
	if strings.Contains(strings.Join(m.targets(), ","), "ytspeed") {
		t.Fatal("disabled video tests retained")
	}
}
func TestZapretVideoDiscoveryParsing(t *testing.T) {
	if zPlayerJS.FindString(`<script src="/s/player/abc123/player_ias.vflset/en_US/base.js"></script>`) != "/s/player/abc123/player_ias.vflset/en_US/base.js" {
		t.Fatal("modern player URL lost")
	}
	if zVideoMapping.FindString("mapping: sn-abc-123") != "sn-abc-123" {
		t.Fatal("mapping parser")
	}
}

type siteCheckSys struct {
	Sys
	rules, tables string
	mutations     int
}

func (s *siteCheckSys) Run(d time.Duration, in, name string, args ...string) (string, int) {
	switch name + " " + strings.Join(args, " ") {
	case "ip -4 rule show pref 1198":
		return s.rules, 0
	case "nft list tables":
		return s.tables, 0
	case "nft -f -", "nft delete table inet vpnguard_zapret_probe", "ip rule add fwmark 0x1e lookup main priority 1198", "ip rule del fwmark 0x1e lookup main priority 1198":
		s.mutations++
	}
	if name == "curl" {
		return "000 0 0.1 0 0", 6
	}
	return s.Sys.Run(d, in, name, args...)
}

func TestShareableZapretDiagnostic(t *testing.T) {
	sim := setup(t)
	spy := &siteCheckSys{Sys: sim}
	S = spy
	setCfg("zapret.videoCheck", "false")
	setCfg("zapret.targets", "https://www.youtube.com,https://user:password@example.invalid/private?token=secret")
	check := mod("zapret").Checks()[1]
	f := check.Run()
	if f.OK || len(f.Report) != 2 || !strings.Contains(f.Report[0], "www.youtube.com") || !strings.Contains(f.Report[1], "Своя цель №2") || !strings.Contains(f.Report[1], "DNS") {
		t.Fatalf("unexpected report: %+v", f)
	}
	for _, secret := range []string{"example.invalid", "secret", "private", "password"} {
		if strings.Contains(strings.Join(f.Report, " "), secret) {
			t.Fatal("custom target leaked")
		}
	}
	spy.rules = "1198: from all lookup 201"
	for _, want := range []string{"1198", "nftables"} {
		spy.mutations = 0
		f = check.Run()
		if f.OK || !f.SkipFix || len(f.Report) != 1 || !strings.Contains(f.Report[0], want) || spy.mutations != 0 {
			t.Fatalf("unsafe or stale result: %+v, mutations=%d", f, spy.mutations)
		}
		spy.rules = ""
		spy.tables = "table inet vpnguard_zapret_probe"
	}
}
