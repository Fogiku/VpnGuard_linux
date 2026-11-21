package main

import (
	"fmt"
	"regexp"
	"strings"
)

// The tunnel is managed by the administrator. VpnGuard only monitors it and routes clients.
type wireGuardExit struct {
	base
	iface string
}

var extraIfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

func (m *wireGuardExit) ID() string    { return "wg-out-" + m.iface }
func (m *wireGuardExit) Name() string  { return "WireGuard · " + m.iface }
func (m *wireGuardExit) Color() string { return "#68a8d6" }
func (m *wireGuardExit) Exit() *Exit   { return &Exit{Iface: m.iface, AutoRoutes: true} }
func (m *wireGuardExit) Tick() {
	m.tk.Lock()
	defer m.tk.Unlock()
	if m.iface == wgMod.iface() || m.iface == wanIface() || m.iface == cfg("awg.active", "awg0") {
		m.setSt(2, false, "Конфликт интерфейса", "Интерфейс уже используется основным модулем шлюза")
		return
	}
	if mdz := mod("meduza"); mdz != nil && mdz.Exit().Iface == m.iface {
		m.setSt(2, false, "Конфликт интерфейса", "Интерфейс уже используется MeduzaVPN")
		return
	}
	peers, code := run("wg", "show", m.iface, "peers")
	if code != 0 || len(strings.Fields(peers)) == 0 {
		m.setSt(2, false, "Туннель недоступен", "Проверьте интерфейс WireGuard и наличие пира")
		return
	}
	if !probe(m.iface, cfg("vpn.probeUrl", "https://1.1.1.1")) {
		m.setSt(2, false, "Нет трафика", "Проверка через туннель не прошла")
		return
	}
	m.setSt(0, true, "Подключено", "")
}

func configuredWireGuardExits(value string) ([]*wireGuardExit, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var exits []*wireGuardExit
	used := map[string]bool{wgMod.iface(): true, cfg("awg.active", "awg0"): true, cfg("net.wan", ""): true, "lo": true}
	for _, field := range strings.Split(value, ",") {
		if len(exits) >= 96 {
			return nil, fmt.Errorf("vpn.extraWireGuard: доступно не более 96 таблиц")
		}
		name := strings.TrimSpace(field)
		if !extraIfaceName.MatchString(name) || used[name] {
			return nil, fmt.Errorf("vpn.extraWireGuard: недопустимый или занятый интерфейс %q", name)
		}
		used[name] = true
		exits = append(exits, &wireGuardExit{iface: name})
	}
	return exits, nil
}
