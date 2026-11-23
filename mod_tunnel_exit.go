package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The tunnel is managed by the administrator. VpnGuard only monitors it and routes clients.
type tunnelExit struct {
	base
	iface  string
	olcRTC bool
}

var extraIfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

func (m *tunnelExit) ID() string {
	if m.olcRTC {
		return "olcrtc-out-" + m.iface
	}
	return "wg-out-" + m.iface
}
func (m *tunnelExit) Name() string {
	if m.olcRTC {
		return "olcRTC · " + m.iface
	}
	return "WireGuard · " + m.iface
}
func (m *tunnelExit) Color() string { return "#68a8d6" }
func (m *tunnelExit) Exit() *Exit   { return &Exit{Iface: m.iface, AutoRoutes: true, TCPOnly: m.olcRTC} }
func (m *tunnelExit) Tick() {
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
	if m.olcRTC {
		raw, err := S.ReadFile("/sys/class/net/" + m.iface + "/tun_flags")
		flags, parseErr := strconv.ParseUint(strings.TrimSpace(raw), 0, 32)
		if err != nil || parseErr != nil || flags&3 != 1 {
			m.setSt(2, false, "Нет TUN-интерфейса", "Проверьте адаптер tun2socks для olcRTC")
			return
		}
	} else {
		peers, code := run("wg", "show", m.iface, "peers")
		if code != 0 || len(strings.Fields(peers)) == 0 {
			m.setSt(2, false, "Туннель недоступен", "Проверьте интерфейс WireGuard и наличие пира")
			return
		}
	}
	if !probe(m.iface, cfg("vpn.probeUrl", "https://1.1.1.1")) {
		m.setSt(2, false, "Нет трафика", "Проверка через туннель не прошла")
		return
	}
	var counters [][2]string
	if m.olcRTC {
		rx, _ := S.ReadFile("/sys/class/net/" + m.iface + "/statistics/rx_bytes")
		tx, _ := S.ReadFile("/sys/class/net/" + m.iface + "/statistics/tx_bytes")
		counters = append(counters, [2]string{"Принято через TUN", olcBytes(rx)}, [2]string{"Передано через TUN", olcBytes(tx)})
	}
	m.setSt(0, true, "Подключено", "", counters...)
}

func configuredTunnelExits(wireGuard, olcRTC string) ([]*tunnelExit, error) {
	var exits []*tunnelExit
	used := map[string]bool{wgMod.iface(): true, cfg("awg.active", "awg0"): true, cfg("net.wan", ""): true, "lo": true}
	for _, list := range []struct{ key, value string }{{"vpn.extraWireGuard", wireGuard}, {"vpn.olcRTC", olcRTC}} {
		if strings.TrimSpace(list.value) == "" {
			continue
		}
		for _, field := range strings.Split(list.value, ",") {
			if len(exits) >= 96 {
				return nil, fmt.Errorf("%s: доступно не более 96 общих таблиц", list.key)
			}
			name := strings.TrimSpace(field)
			if !extraIfaceName.MatchString(name) || used[name] {
				return nil, fmt.Errorf("%s: недопустимый или занятый интерфейс %q", list.key, name)
			}
			used[name] = true
			exits = append(exits, &tunnelExit{iface: name, olcRTC: list.key == "vpn.olcRTC"})
		}
	}
	return exits, nil
}
