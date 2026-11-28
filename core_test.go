package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Проверки логики на имитации: без изменений в системе.
func setup(t *testing.T) *simSys {
	t.Helper()
	DataDir = t.TempDir()
	if m, ok := mod("meduza").(*meduza); ok {
		t.Cleanup(func() {
			m.loginWork.Wait()
			m.pingRun.Lock()
			m.pingRun.Unlock()
		})
	}
	Sim = true
	limMu.Lock()
	delete(limits, "zapret.pick")
	limMu.Unlock()
	sim := newSim()
	S = sim
	cfgMap = map[string]string{}
	wgMod.d = wgData{}
	wgMod.ensure()
	for _, n := range []string{"Телефон", "Телевизор"} {
		if _, err := wgMod.add(n); err != nil {
			t.Fatal(err)
		}
	}
	rt = defaultRoutes()
	for _, m := range Mods {
		m.Tick()
	}
	return sim
}
func TestFailoverAndRecovery(t *testing.T) {
	sim := setup(t)
	if eff, _, _ := resolveExit("meduza", rt.Policy); eff != "meduza" {
		t.Fatalf("ожидался выход meduza, получен %s", eff)
	}
	// ULTRA заблокирован: лестница должна найти другой протокол, выбранный в настройках не меняется
	sim.SetFault("meduza.server", true)
	m := mod("meduza").(*meduza)
	for i := 0; i < 5 && m.override == ""; i++ {
		m.Tick()
	}
	if !m.Status().Up || m.override == "" || cfg("meduza.protocol", "ultra") != "ultra" {
		t.Fatalf("автоподбор протокола не сработал: up=%v override=%q", m.Status().Up, m.override)
	}
	// служба упала и интернет пропал: выход недоступен → резерв, затем блокировка
	sim.SetFault("meduza.daemon", true)
	sim.SetFault("meduza.login", true)
	m.Tick()
	m.Tick()
	if eff, state, _ := resolveExit("meduza", rt.Policy); eff != "awg" || state != "warn" {
		t.Fatalf("ожидался резерв awg, получено %s/%s", eff, state)
	}
	sim.SetFault("awg.server", true)
	mod("awg").Tick()
	if eff, _, why := resolveExit("meduza", rt.Policy); eff != "block" || why == "" {
		t.Fatalf("ожидалась блокировка, получено %s", eff)
	}
	rt.Policy["meduza"] = ExitPolicy{Reserve: "awg", IfDown: "direct"}
	if eff, _, _ := resolveExit("meduza", rt.Policy); eff != "direct" {
		t.Fatalf("ожидался выход напрямую, получено %s", eff)
	}
}
func TestZapretRepick(t *testing.T) {
	sim := setup(t)
	z := mod("zapret").(*zapret2)
	if !z.Status().Up || z.running != "fake + multisplit" {
		t.Fatalf("первый подбор: up=%v стратегия=%q", z.Status().Up, z.running)
	}
	sim.SetFault("zapret.dpi", true)
	for i := 0; i < 3; i++ {
		z.checkedAt = time.Now().Add(-11 * time.Minute) // next scheduled health check
		z.Tick()
	}
	if !z.Status().Up || z.running != "hostfakesplit" {
		t.Fatalf("переподбор после смены блокировки: up=%v стратегия=%q", z.Status().Up, z.running)
	}
}
func TestCompileAndValidate(t *testing.T) {
	setup(t)
	rt.Overrides[wgMod.subnet()+".2"] = []Rule{{ID: "o1", Title: "Игры", Preset: "games", Exit: "direct"}}
	script, ipCmds := Compile()
	for _, want := range []string{"table inet vpnguard", "ip saddr 10.253.0.2 udp dport 27000-27100", "meta mark set 0x13", "queue num 200 bypass", "masquerade"} {
		if !strings.Contains(script, want) {
			t.Errorf("в сценарии нет %q", want)
		}
	}
	if strings.Index(script, "ov_") > strings.Index(script, "ip saddr @c_p1") {
		t.Error("правила клиента должны стоять выше правил профиля")
	}
	if len(ipCmds) == 0 {
		t.Error("нет команд ip для таблиц туннелей")
	}
	bad := defaultRoutes()
	bad.Profiles[0].Rules[0].Match, bad.Profiles[0].Rules[0].Preset = "это не адрес!", ""
	if validateRoutes(&bad) == nil {
		t.Error("неверное условие правила должно отклоняться")
	}
	bad = defaultRoutes()
	bad.Profiles[0].Rules = bad.Profiles[0].Rules[:1]
	if validateRoutes(&bad) == nil {
		t.Error("профиль без правила «всё остальное» должен отклоняться")
	}
}
func TestParsersAndLimits(t *testing.T) {
	if got := pickList(`{"services":[{"id":"nl-1","name":"NL"},{"id":"x","available":false}]}`, "services"); len(got) != 1 || got[0].ID != "nl-1" {
		t.Errorf("pickList: %+v", got)
	}
	if got := pickList(`["ultra","vless2"]`, "protocols"); len(got) != 2 {
		t.Errorf("pickList для простого списка: %+v", got)
	}
	n, err := normalizeAwg("[Interface]\nPrivateKey = a\n[Peer]\nPublicKey = b\nEndpoint = 1.2.3.4:1\n")
	if err != nil || !strings.Contains(n, "Table = off") {
		t.Errorf("normalizeAwg: %v %q", err, n)
	}
	if _, err := normalizeAwg("мусор"); err == nil {
		t.Error("неполная конфигурация должна отклоняться")
	}
	if a, p, err := parseMatch("1.2.3.4, 10.0.0.0/8, udp:53, tcp:1000-2000", false); err != nil || len(a) != 2 || len(p) != 2 {
		t.Errorf("parseMatch: %v %v %v", a, p, err)
	}
	for i := 0; i < 3; i++ {
		if !allow("t", 3, time.Minute) {
			t.Fatal("лимит сработал раньше времени")
		}
	}
	if allow("t", 3, time.Minute) {
		t.Error("четвёртое действие за окно должно быть запрещено")
	}
	_ = os.Remove("data-sim")
}
