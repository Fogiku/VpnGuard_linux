package main

import (
	"sync"
	"time"
)

var draftActivity struct {
	sync.Mutex
	running string
	last    string
	at      time.Time
	wait    string
}

func draftWait(reason string) {
	draftActivity.Lock()
	defer draftActivity.Unlock()
	draftActivity.wait = reason
}

func zapretActivity() map[string]any {
	enabled := cfgBool("flows.enabled", false) && cfgBool("flows.eventsEnabled", false) && cfgBool("flows.dpiEnabled", false) && cfgBool("zapret.passiveDraft", false)
	draftActivity.Lock()
	running, last, at, reason := draftActivity.running, draftActivity.last, draftActivity.at, draftActivity.wait
	draftActivity.Unlock()
	flowsMod.mu.Lock()
	var sample dpiSampleResult
	if n := len(flowsMod.dpiHistory); n > 0 {
		sample = flowsMod.dpiHistory[n-1]
	}
	truncated := flowsMod.truncated
	flowsMod.mu.Unlock()
	switch {
	case !cfgBool("zapret.enabled", true):
		reason = "Модуль zapret2 выключен"
	case !enabled:
		reason = "Автоматический анализ потоков выключен"
	case aiModel() == "":
		reason = "Для генерации выберите локальную модель в zapret2"
	case sample.Status == "":
		reason = "Ожидание первой выборки nDPI"
	case sample.Status != "sample" && sample.Status != "empty":
		reason = sample.Description
	case truncated:
		reason = "Снимок conntrack неполный, ожидание следующего"
	case reason == "":
		reason = "Наблюдение · ожидание повторных признаков сбоя"
	}
	if busy := mod("zapret").Status().Busy; busy != "" {
		reason = busy
	}
	if running != "" {
		reason = "ИИ генерирует стратегию · " + running
	}
	view := map[string]any{"enabled": enabled, "state": reason, "last": last, "source": sample.Source, "sampleAt": sample.At}
	if !at.IsZero() {
		view["lastAt"] = at.UTC().Format(time.RFC3339)
	}
	return view
}
