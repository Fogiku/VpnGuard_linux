package main

import (
	"strings"
	"testing"
)

func TestDiagnosticExplanation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ready       bool
		modules     []diagnosticModuleV1
		summary     string
		observation string
	}{
		{"normal", true, []diagnosticModuleV1{{"wg", 0, true}, {"awg", -1, false}}, "штатное", "журнале"},
		{"warning", true, []diagnosticModuleV1{{"zapret", 1, true}}, "причины", "zapret сообщает: предупреждение (level=1, up=true)"},
		{"failure", true, []diagnosticModuleV1{{"wg", 2, false}}, "причины", "wg сообщает: сбой (level=2, up=false)"},
		{"starting", false, nil, "причины", "готовность маршрутизации"},
		{"empty", true, nil, "Недостаточно", "журнале"},
		{"disabled", true, []diagnosticModuleV1{{"awg", -1, false}}, "Недостаточно", "журнале"},
		{"unknown", true, []diagnosticModuleV1{{"dns", 5, true}}, "причины", "неизвестный уровень"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := explainDiagnosticSnapshot(diagnosticSnapshotV1{Simulation: true, RoutingReady: tc.ready,
				Modules: tc.modules, Decisions: diagnosticDecisionsV1{Warning: 2}})
			if e.SchemaVersion != 1 || !e.Simulation || !strings.Contains(e.Summary, tc.summary) ||
				!strings.Contains(strings.Join(e.Observations, " "), tc.observation) {
				t.Fatalf("unexpected explanation: %+v", e)
			}
		})
	}
}
