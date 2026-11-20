package main

import (
	"testing"
	"time"
)

func TestMeduzaLiveCLIFormat(t *testing.T) {
	items := pickList(`{"services":[{"id":"10008620","name":"Frankfurt-1","country":"de","ipv4":"167.17.190.121"}]}`, "services")
	if len(items) != 1 || items[0].Host != "167.17.190.121" {
		t.Fatalf("server address lost: %+v", items)
	}
	for _, tc := range []struct {
		state map[string]any
		want  bool
	}{
		{map[string]any{"state": "connected"}, true},
		{map[string]any{"state": "connecting"}, false},
		{map[string]any{"state": "disconnected"}, false},
		{map[string]any{"connected": true}, true},
		{map[string]any{"connected": false, "state": "connected"}, false},
	} {
		if got := meduzaConnected(tc.state); got != tc.want {
			t.Errorf("status %v: got %v, want %v", tc.state, got, tc.want)
		}
	}
	setup(t)
	if got := meduzaIface(map[string]any{"interface": "mdz0"}); got != "mdz0" {
		t.Fatalf("explicit CLI interface lost: %s", got)
	}
	setCfg("meduza.iface", "custom0")
	if got := meduzaIface(map[string]any{}); got != "custom0" {
		t.Fatalf("configured interface lost: %s", got)
	}
	setCfg("meduza.iface", "")
	if got := meduzaIface(map[string]any{}); got != "meduza0" {
		t.Fatalf("default interface: %s", got)
	}
}

type meduzaLocationSys struct{ Sys }

func (s meduzaLocationSys) Run(timeout time.Duration, stdin, name string, args ...string) (string, int) {
	if name == "meduzavpn" && len(args) > 1 && args[0] == "list" && args[1] == "--services" {
		return `{"services":[{"id":"10008620","name":"New York-2","country":"us","ipv4":"156.9.98.237"}]}`, 0
	}
	if name == "dpkg-query" {
		return "1.2.80-360", 0
	}
	return s.Sys.Run(timeout, stdin, name, args...)
}
func TestMeduzaExternalLocationRefresh(t *testing.T) {
	setup(t)
	S = meduzaLocationSys{S}
	m := &meduza{
		services: []mdzItem{{ID: "10008620", Name: "Frankfurt-1", Host: "167.17.190.121"}},
		protos:   []mdzItem{{ID: "ultra"}},
		catAt:    time.Now().Add(-2 * time.Minute),
		pings:    map[string]mdzPing{"10008620": {Host: "167.17.190.121", Ms: 25}},
	}
	// Keep the background probe out of this catalog regression test.
	m.pingRun.Lock()
	m.catalog(false)
	if len(m.services) != 1 || m.services[0].Name != "New York-2" {
		t.Fatalf("external location stayed cached: %+v", m.services)
	}
	if p := m.pings["10008620"]; p.Host != "156.9.98.237" || p.Ms != -2 {
		t.Fatalf("old location ping retained: %+v", p)
	}
	m.checkVersion(false)
	if m.ver != "1.2.80+360" {
		t.Fatalf("installed build lost: %s", m.ver)
	}
}
