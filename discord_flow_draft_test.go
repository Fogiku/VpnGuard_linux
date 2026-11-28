package main

import (
	"strings"
	"testing"
	"time"
)

func TestDiscordFlowEvidence(t *testing.T) {
	now := time.Now()
	first := discordSample{UTC: now.Add(-90 * time.Second), ControlUTC: now.Add(-70 * time.Second), Outcome: "timeout", ControlHTTP: 204, ControlTLS: true, Policy: strings.Repeat("a", 64), Profile: strings.Repeat("b", 64), Correlation: "pin_and_observed_policy", ControlCorrelation: "pin_and_observed_policy", Exit: "zapret"}
	first.ControlPolicy = first.Policy
	second := first
	second.UTC = now.Add(-50 * time.Second)
	second.ControlUTC = now.Add(-30 * time.Second)
	if msg := discordEvidence([]discordSample{first, second}, now); msg != "" {
		t.Fatal(msg)
	}
	for _, change := range []func(*discordSample){
		func(s *discordSample) { s.ControlHTTP = 503 }, func(s *discordSample) { s.Exit = "direct" },
		func(s *discordSample) { s.Profile = strings.Repeat("c", 64) }, func(s *discordSample) { s.Policy = "" },
		func(s *discordSample) { s.Outcome = "hello" }, func(s *discordSample) { s.UTC = first.UTC },
		func(s *discordSample) { s.Correlation = "ambiguous" }, func(s *discordSample) { s.Outcome = "connection_error" },
	} {
		broken := second
		change(&broken)
		if discordEvidence([]discordSample{first, broken}, now) == "" {
			t.Fatal(broken)
		}
	}
}
