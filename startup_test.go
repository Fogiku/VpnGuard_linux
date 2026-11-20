package main

import (
	"strings"
	"testing"
)

func TestStartupPreservesInstalledRoutes(t *testing.T) {
	s := transactionSetup(t)
	routesStarting.Store(true)
	defer routesStarting.Store(false)
	if err := Apply("early module event"); err == nil {
		t.Fatal("startup apply should be deferred")
	}
	if len(s.commands) != 0 {
		t.Fatalf("kernel touched during startup: %v", s.commands)
	}
}

func TestRestartAdoptsNfqwsWithoutRestart(t *testing.T) {
	s := transactionSetup(t)
	old := mod("zapret").(*zapret2)
	m := &zapret2{strat: append([]zStrategy(nil), old.strat...)}
	m.Tick()
	if m.running == "" || !m.Status().Up {
		t.Fatalf("existing nfqws not adopted: %+v", m.Status())
	}
	for _, cmd := range s.commands {
		if strings.Contains(cmd, "systemctl restart vpnguard-nfqws2") {
			t.Fatal("working nfqws was restarted")
		}
	}
}

// Отдельный экземпляр загружает сохранённый WG без повторного syncconf.
func TestRestartLoadsWgWithoutSync(t *testing.T) {
	s := transactionSetup(t)
	m := &wgServer{}
	m.ensure()
	if m.d.Priv == "" {
		t.Fatal("saved WG state missing")
	}
	for _, cmd := range s.commands {
		if strings.Contains(cmd, "wg syncconf") {
			t.Fatal("unchanged WG configuration was reapplied")
		}
	}
}
