package main

import (
	"runtime"
	"testing"
)

func TestStateReadsOneRoutePolicy(t *testing.T) {
	oldMods, oldRt, oldDir, oldSim, oldSys := Mods, rt, DataDir, Sim, S
	t.Cleanup(func() { Mods, rt, DataDir, Sim, S = oldMods, oldRt, oldDir, oldSim, oldSys })
	DataDir, Sim, S = t.TempDir(), true, newSim()
	meduza := &flowTestExit{id: "meduza", mark: 0x11, table: 101}
	direct := &flowTestExit{id: "direct", mark: 0x14}
	direct.setSt(0, true, "up", "")
	Mods = []Module{meduza, direct}
	rt = defaultRoutes()
	rt.Profiles[0].Rules = []Rule{{ID: "all", Exit: "meduza", Last: true}}
	blocked := map[string]ExitPolicy{}
	viaDirect := map[string]ExitPolicy{"meduza": {IfDown: "direct"}}
	rt.Policy = blocked
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			for _, policy := range []map[string]ExitPolicy{viaDirect, blocked} {
				rtMu.Lock()
				rt.Policy = policy
				rtMu.Unlock()
				runtime.Gosched()
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	defer func() { close(stop); <-done }()
	for i := 0; i < 128; i++ {
		routes := buildState()["routes"].(map[string]any)
		exit := routes["exits"].([]map[string]any)[0]
		profile := routes["profiles"].([]map[string]any)[0]
		rule := profile["rules"].([]ruleView)[0]
		if exit["ifDown"] != rule.Eff || (rule.Eff != "block" && rule.Eff != "direct") {
			t.Fatalf("inconsistent route state: ifDown=%v, effective exit=%s", exit["ifDown"], rule.Eff)
		}
	}
}
