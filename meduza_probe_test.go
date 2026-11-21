package main

import (
	"strings"
	"testing"
	"time"
)

type meduzaProbeSys struct {
	Sys
	iface   string
	success string
	urls    []string
}

func (s *meduzaProbeSys) Run(d time.Duration, input, name string, args ...string) (string, int) {
	if name == "curl" && strings.Contains(strings.Join(args, " "), "--interface "+s.iface+" ") {
		target := args[len(args)-1]
		s.urls = append(s.urls, target)
		if target == s.success {
			return "302 0.1", 0
		}
		return "000 6", 28
	}
	return s.Sys.Run(d, input, name, args...)
}

func TestMeduzaConfirmsFailedProbeBeforeBlocking(t *testing.T) {
	setup(t)
	m := mod("meduza").(*meduza)
	old := S
	t.Cleanup(func() { S = old })
	s := &meduzaProbeSys{Sys: old, iface: m.iface}
	S = s
	rt.Policy["meduza"] = ExitPolicy{IfDown: "block"}
	for _, tc := range []struct {
		primary, success, calls, exit string
		level                         int
	}{
		{"https://1.1.1.1", "https://1.1.1.1", "https://1.1.1.1", "meduza", 0},
		{"https://1.1.1.1", "https://8.8.8.8", "https://1.1.1.1 https://8.8.8.8", "meduza", 1},
		{"https://8.8.8.8/", "https://1.1.1.1", "https://8.8.8.8/ https://1.1.1.1", "meduza", 1},
		{"https://1.1.1.1", "", "https://1.1.1.1 https://8.8.8.8", "block", 2},
	} {
		if err := setCfg("vpn.probeUrl", tc.primary); err != nil {
			t.Fatal(err)
		}
		s.success, s.urls = tc.success, nil
		m.Tick()
		st := m.Status()
		eff, _, _ := resolveExit("meduza", rt.Policy)
		if strings.Join(s.urls, " ") != tc.calls || st.Level != tc.level || eff != tc.exit {
			t.Fatalf("calls=%v level=%d effective=%s", s.urls, st.Level, eff)
		}
	}
}
