package main

import "testing"

func TestDiagnosticTelemetryWindow(t *testing.T) {
	s := &historyStore{}
	for _, at := range []int64{300, 305, 310, 320, 600, 605} {
		s.add(at, map[string]float64{"dns.errors": 0, "client.192.0.2.1": 2, "dns.private": 1})
	}
	s.add(610, map[string]float64{"client.private": 1})
	page := s.diagnosticWindow(603)
	if page.From != 305 || page.Through != 600 || page.StepSeconds != 5 || len(page.Samples) != 4 {
		t.Fatal(page)
	}
	for i, at := range []int64{305, 310, 320, 600} {
		sample := page.Samples[i]
		v, ok := sample.Values["dns.errors"]
		if sample.At != at || !ok || v != 0 || len(sample.Values) != 1 {
			t.Fatal(sample)
		}
	}
	page.Samples[0].Values["dns.errors"] = 9
	if s.diagnosticWindow(603).Samples[0].Values["dns.errors"] != 0 {
		t.Fatal("response aliases stored sample")
	}
	if got := s.diagnosticWindow(906).Samples; len(got) != 0 || got == nil {
		t.Fatal("expected empty array", got)
	}
}
