package main

import (
	"strings"
	"testing"
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
