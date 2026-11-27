package main

import (
	"testing"
	"time"
)

type setupResult struct {
	Sys
	code int
}

func (s setupResult) Stream(_ time.Duration, _ string, progress func(string), _ string, _ ...string) int {
	progress("Загрузка модели")
	return s.code
}

func TestLocalAISelection(t *testing.T) {
	setup(t)
	t.Setenv("VPNGUARD_ZAPRET_MODEL", "previous")
	model := localModels[0].V
	if _, err := setupLocalAI("unknown"); err == nil {
		t.Fatal("accepted unknown model")
	}
	var status string
	report := func(s string) { status = s }
	if _, err := prepareLocalAI(setupResult{code: 1}, model, report); err == nil || aiModel() != "previous" {
		t.Fatal("failed installation changed active model")
	}
	if _, err := prepareLocalAI(setupResult{}, model, report); err != nil || aiModel() != model || status != "Загрузка модели" {
		t.Fatalf("selection failed: %q %q %v", aiModel(), status, err)
	}
}
