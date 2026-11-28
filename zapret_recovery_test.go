package main

import (
	"testing"
	"time"
)

func TestRecoveryPolicy(t *testing.T) {
	setup(t)
	m := &zapret2{}
	partial := siteCheck{passed: 1, total: 2}
	down := siteCheck{total: 2}
	if m.recoveryDue("any", partial) || !m.recoveryDue("any", down) {
		t.Fatal("default threshold")
	}
	if m.recoveryDue("all", partial) || m.recoveryDue("all", down) || !m.recoveryDue("all", down) {
		t.Fatal("total outage threshold")
	}
	for _, mode := range []string{"observe", "unknown"} {
		if m.recoveryDue(mode, down) || m.fails != 0 {
			t.Fatal(mode)
		}
	}
	if m.recoveryDue("any", down) || m.recoveryDue("any", siteCheck{setupError: "unavailable"}) || m.recoveryDue("any", down) {
		t.Fatal("probe setup failure counted")
	}
	if err := setCfg("zapret.strategy", "fake"); err != nil {
		t.Fatal(err)
	}
	if m.recoveryDue("any", down) || m.fails != 0 {
		t.Fatal("pinned strategy")
	}
	for key, value := range map[string]string{"zapret.recoveryMode": "bad", "zapret.recoveryLimit": "0", "zapret.recoveryFailures": "11"} {
		if err := m.Set(key, value); err == nil {
			t.Fatal(key)
		}
	}
}

func TestRecoveryFromSimulatedGatewayFailure(t *testing.T) {
	sim := setup(t)
	m := &zapret2{}
	for key, value := range map[string]string{"zapret.targets": "youtube.com", "zapret.videoCheck": "false", "zapret.settleMs": "0", "zapret.recoveryMode": "observe", "zapret.picked": "fake + multisplit"} {
		if err := setCfg(key, value); err != nil {
			t.Fatal(err)
		}
	}
	sim.SetFault("zapret.dpi", true)
	m.Tick()
	if m.running != "fake + multisplit" || m.Status().Up {
		t.Fatal("observe", m.running, m.Status())
	}
	if err := setCfg("zapret.recoveryMode", "all"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		m.checkedAt = time.Time{}
		m.Tick()
		if i == 0 && m.running != "fake + multisplit" {
			t.Fatal("changed before threshold")
		}
	}
	if m.running != "hostfakesplit" || !m.Status().Up || m.Status().Level != 0 || m.want() != m.running {
		t.Fatal("recovery", m.running, m.Status())
	}
	loadCfg()
	last := latestReserveRecovery()
	if last == nil || last.Status != "Резерв принят" || len(last.Attempts) != 3 || last.Attempts[2].Revision != draftHash(m.strat[m.index(m.want())].Args) {
		t.Fatal("committed reserve record", last)
	}
}

func TestInterruptedReserveUsesCommittedProfile(t *testing.T) {
	setup(t)
	m := &zapret2{strat: builtinZapretStrategies()}
	if err := setCfg("zapret.picked", m.strat[1].Name); err != nil {
		t.Fatal(err)
	}
	attempt := reserveRecovery{Original: draftHash(m.strat[1].Args), Attempts: []reserveAttempt{{Revision: draftHash(m.strat[0].Args), Result: "Проверка начата"}}}
	if err := attempt.save("Начата проверка резерва", ""); err != nil {
		t.Fatal(err)
	}
	if !m.apply(0) {
		t.Fatal(m.startErr)
	}
	loadCfg()
	restarted := &zapret2{}
	restarted.Tick()
	raw, err := S.ReadFile(zArgs)
	if err != nil || raw != m.strat[1].Args+"\n" || restarted.running != m.strat[1].Name {
		t.Fatal(restarted.running, err)
	}
	last := latestReserveRecovery()
	if last == nil || last.Status != "Начата проверка резерва" || len(last.Attempts) != 1 || last.Attempts[0] != attempt.Attempts[0] {
		t.Fatal(last)
	}
}
