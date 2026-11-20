package main

import "testing"

func TestReleaseUpgradeOrder(t *testing.T) {
	for _, test := range []struct {
		next, current string
		newer         bool
	}{
		{"1.10", "1.9.2", true}, {"1.9.2", "1.9", true}, {"1.9.0", "1.9", false},
		{"1.8.9", "1.9", false}, {"1.9/../main", "1.9", false}, {"1.9.1", "", false},
	} {
		if got := newerRelease(test.next, test.current); got != test.newer {
			t.Errorf("newerRelease(%q, %q) = %t", test.next, test.current, got)
		}
	}
}
