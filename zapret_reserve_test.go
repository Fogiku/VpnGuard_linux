package main

import (
	"testing"
	"time"
)

func TestReserveSelectionAndTargetRegression(t *testing.T) {
	m := zapret2{strat: builtinZapretStrategies()}
	m.strat = append(m.strat, zStrategy{Name: "new", Args: "candidate", Qualified: true}, zStrategy{Name: "duplicate", Args: m.strat[0].Args})
	slots := m.reserveIndices(0)
	if len(slots) != 3 || slots[0] != 4 || slots[1] != 1 || slots[2] != 2 {
		t.Fatal(slots)
	}
	base := siteCheck{results: map[string]bool{"discord": false, "youtube": true, "control": true}}
	for _, test := range []struct {
		results map[string]bool
		ok      bool
	}{
		{map[string]bool{"discord": true, "youtube": true, "control": true}, true},
		{map[string]bool{"discord": true, "youtube": false, "control": true}, false},
		{map[string]bool{"discord": true, "control": true}, false}, {base.results, false},
	} {
		if improvesTargets(base, siteCheck{results: test.results}) != test.ok {
			t.Fatal(test)
		}
	}
}

func TestReserveAdmission(t *testing.T) {
	now := time.Now().UTC()
	d := zapretDraft{BaseSHA256: "base", SHA256: "candidate", Scenario: "discord"}
	series := func(before, outcome string) reserveSeries {
		pairs := []reservePair{}
		for _, ago := range []time.Duration{3 * time.Minute, time.Minute} {
			ts := now.Add(-ago)
			pairs = append(pairs, reservePair{UTC: []time.Time{ts, ts.Add(time.Second)}, States: []string{before, "observed"}})
		}
		return reserveSeries{Pairs: pairs, Outcome: outcome}
	}
	report := reserveReport{Schema: 1, Source: "paired_client_browser", ProfileSource: "file_sha256", Profiles: []string{"base", "candidate"}, Comparison: map[string]reserveSeries{"youtube": series("observed", "both_observed"), "discord_gateway": series("failure", "only_second_observed")}}
	if err := report.qualifies(d, now); err != nil {
		t.Fatal(err)
	}
	if err := report.qualifies(d, now.Add(25*time.Hour)); err == nil {
		t.Fatal("accepted stale series")
	}
	report.Comparison["youtube"].Pairs[0].States[1] = "failure"
	if err := report.qualifies(d, now); err == nil {
		t.Fatal("accepted regressed YouTube")
	}
	delete(report.Comparison, "youtube")
	if err := report.qualifies(d, now); err == nil {
		t.Fatal("accepted missing protected service")
	}
}

func TestZapretUnansweredSnapshot(t *testing.T) {
	reply := false
	id := uint32(15)
	row := flowRow{ConntrackID: &id, Protocol: "tcp", Mark: 19 << 16, SeenReply: &reply}
	rows := []flowRow{row}
	if len(repeatedUnanswered(rows, rows, true)) != 1 || len(repeatedUnanswered(rows, rows, false)) != 0 {
		t.Fatal("snapshot continuity")
	}
	for _, mutate := range []func(*flowRow){func(r *flowRow) { r.Mark = 20 << 16 }, func(r *flowRow) { r.DestinationPort++ }, func(r *flowRow) { r.SeenReply = nil }, func(r *flowRow) { yes := true; r.SeenReply = &yes }} {
		next := row
		mutate(&next)
		if len(repeatedUnanswered(rows, []flowRow{next}, true)) != 0 {
			t.Fatal(next)
		}
	}
}
