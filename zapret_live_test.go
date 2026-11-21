package main

import (
	"strings"
	"sync"
	"testing"
	"time"
)

type zapretProbeSys struct {
	Sys
	mu        sync.Mutex
	script    string
	localPort bool
	bindIP    bool
	failStart bool
}

func (s *zapretProbeSys) Run(d time.Duration, in, name string, args ...string) (string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name == "nft" && strings.HasPrefix(in, "create table inet vpnguard_zapret_probe") {
		s.script = in
	}
	if s.failStart && name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
		return "failed", 3
	}
	if name == "curl" {
		for i, a := range args {
			if a == "--interface" && i+1 < len(args) && args[i+1] == "192.168.1.50" {
				s.bindIP = true
			}
			if a == "--local-port" && i+1 < len(args) && args[i+1] == "42000-42099" {
				s.localPort = true
			}
		}
	}
	return s.Sys.Run(d, in, name, args...)
}
func TestZapretProbeRouting(t *testing.T) {
	setup(t)
	capture := &zapretProbeSys{Sys: S}
	S = capture
	m := mod("zapret").(*zapret2)
	m.check()
	if !capture.localPort || !capture.bindIP || !strings.Contains(capture.script, "type route hook output") || !strings.Contains(capture.script, "meta mark set 0x1e") || !strings.Contains(capture.script, "hook postrouting") {
		t.Fatalf("probe misses bypass route/queue: %s", capture.script)
	}
	_, commands := Compile()
	var zapret, direct bool
	for _, c := range commands {
		s := strings.Join(c, " ")
		zapret = zapret || strings.Contains(s, "rule add fwmark 0x13 lookup main")
		direct = direct || strings.Contains(s, "rule add fwmark 0x14 lookup main")
	}
	if !zapret || !direct {
		t.Fatal("direct exits must take priority over VPN default route")
	}
	capture.failStart = true
	if m.apply(0) || m.running != "" || m.startErr == "" {
		t.Fatal("failed nfqws2 incorrectly reported running")
	}
}
