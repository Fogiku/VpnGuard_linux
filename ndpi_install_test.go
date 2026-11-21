package main

import (
	"slices"
	"strings"
	"testing"
	"time"
)

type ndpiInstallSys struct {
	Sys
	candidates []string
	versions   []string
	aptCode    int
	calls      []string
}

func (s *ndpiInstallSys) Run(_ time.Duration, _ string, name string, args ...string) (string, int) {
	s.calls = append(s.calls, name+" "+strings.Join(args, " "))
	if name == "ndpiReader" {
		if len(s.versions) == 0 {
			return "", -1
		}
		v := s.versions[0]
		s.versions = s.versions[1:]
		return "extcap {version=" + v + "}\n", 1
	}
	if slices.Contains(args, "apt-cache") {
		v := s.candidates[0]
		s.candidates = s.candidates[1:]
		return "  Candidate: " + v + "\n", 0
	}
	return "", s.aptCode
}

func TestNDPIInstallation(t *testing.T) {
	const pkg = "4.2-2.1build1"
	for _, tc := range []struct {
		name                string
		sys                 ndpiInstallSys
		ok, update, install bool
	}{
		{"installed", ndpiInstallSys{versions: []string{"4.2.0"}}, true, false, false},
		{"refresh", ndpiInstallSys{candidates: []string{"(none)", pkg}, versions: []string{"", "4.2.0"}}, true, true, true},
		{"incompatible candidate", ndpiInstallSys{candidates: []string{"4.12-1"}}, false, false, false},
		{"unavailable", ndpiInstallSys{candidates: []string{"(none)", "(none)"}}, false, true, false},
		{"apt failure", ndpiInstallSys{candidates: []string{pkg}, aptCode: 100}, false, false, true},
		{"reader mismatch", ndpiInstallSys{candidates: []string{pkg}, versions: []string{"", "4.12.0"}}, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := installNDPI(&tc.sys)
			calls := strings.Join(tc.sys.calls, "\n")
			if (err == nil) != tc.ok || strings.Contains(calls, " update") != tc.update || strings.Contains(calls, "libndpi-bin="+pkg) != tc.install {
				t.Fatal(err, calls)
			}
		})
	}
	if slices.Contains(remoteCmds(), "flows."+ndpiInstallAction) {
		t.Fatal("diagnostic token can request installation")
	}
	m := &flowModule{}
	m.installMu.Lock()
	if _, err := m.Do(ndpiInstallAction, nil); err == nil {
		t.Fatal("duplicate installation accepted")
	}
	m.installMu.Unlock()
}
