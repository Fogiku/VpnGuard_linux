// Простые модули: «Интернет» (провайдер и состояние системы) и два выхода без служб — «Напрямую» и «Заблокировать».
package main

import (
	"fmt"
	"strings"
	"time"
)

var wanCache string

func wanIface() string {
	if w := cfg("net.wan", ""); w != "" {
		return w
	}
	if wanCache == "" {
		out, _ := run("ip", "route", "get", "1.1.1.1")
		f := strings.Fields(out)
		for i, x := range f {
			if x == "dev" && i+1 < len(f) {
				wanCache = f[i+1]
			}
		}
	}
	return wanCache
}

type inet struct {
	base
	fails int
}

func init()                           { Register(&inet{}); Register(&direct{}); Register(&block{}) }
func (m *inet) ID() string            { return "inet" }
func (m *inet) Name() string          { return "Интернет" }
func (m *inet) Color() string         { return "#9fb3c8" }
func (m *inet) Order() int            { return 1 }
func (m *inet) Period() time.Duration { return 10 * time.Second }

// Своей вкладки нет: состояние провайдера — на главной, проверки системы и настройки — в диагностике.
func (m *inet) NoPage() bool { return true }
func (m *inet) Tick() {
	m.tk.Lock()
	defer m.tk.Unlock()
	w := wanIface()
	ok := probe(w, "https://1.1.1.1") || probe(w, "https://77.88.8.8")
	if ok {
		if m.fails >= 2 {
			Decide("INFO", "Интернет провайдера восстановлен")
			Emit("inet.restored", "")
		}
		m.fails = 0
		m.setSt(0, true, "Есть связь", "", [2]string{"Интерфейс", w})
		return
	}
	m.fails++
	if m.fails == 2 {
		Decide("ERROR", "Провайдер не отвечает (%s) → туннели не перезапускаются, ждём восстановления связи", w)
		Emit("inet.lost", "")
	}
	m.setSt(2, false, "Нет связи", "провайдер не отвечает: это не сбой VPN", [2]string{"Интерфейс", w})
}
func (m *inet) Fields() []Field {
	fields := []Field{fb("modules.olc", "Включить olcRTC", "bool", "false", "Показывает модуль и сохранённые профили. Службы устройств запускаются отдельно."), fb("net.wan", "Интерфейс провайдера", "text", "", "Пусто — определять автоматически"),
		fb("vpn.extraWireGuard", "Дополнительные выходы WireGuard", "text", "", "Имена настроенных исходящих интерфейсов через запятую. Список вступает в силу после перезапуска VpnGuard."),

		fb("vpn.probeUrl", "Адрес для проверки туннелей", "text", "https://1.1.1.1", ""),
		fb("net.qualityEnabled", "Измерять качество соединений", "bool", "true", "Пять ICMP-пакетов примерно раз в 30 секунд через WAN и активные VPN. Измерения не переключают маршруты."),
		fb("net.qualityIP", "IPv4-адрес для измерений", "text", "1.1.1.1", "Один контрольный адрес для RTT, потерь ICMP и изменения RTT. Отсутствие ping не означает недоступность приложений."),
		fb("net.localNetworks", "Локальные сети без VPN", "textarea", "", "IPv4-подсети через запятую. Доступ к этим сетям, SSH и вебу шлюза не отправляется в VPN."),
		fb("net.pinFlows", "Сохранять маршрут соединений", "bool", "false", "Новые правила действуют на новые соединения. При отказе выхода существующие потоки блокируются до его восстановления. Выключение разрешает смену пути действующих соединений.")}
	if cfgBool("modules.olc", false) {
		fields = append(fields, fb("vpn.olcRTC", "Выходы olcRTC (TCP)", "text", "", "Имена TUN-интерфейсов tun2socks через запятую. Настройте клиент olcRTC и адаптер, сохраните список и перезапустите VpnGuard."))
	}
	return fields
}
func (m *inet) Set(key, value string) error {
	if key == "modules.olc" {
		olcControl.Lock()
		defer olcControl.Unlock()
		if value != "true" && value != "false" {
			return fmt.Errorf("неверное значение")
		}
		if value == "false" && !Sim {
			if err := stopOlcServices(); err != nil {
				return err
			}
		}
		return setCfg(key, value)
	}
	if key == "vpn.extraWireGuard" || key == "vpn.olcRTC" {
		m.tk.Lock()
		defer m.tk.Unlock()
		wg, olc := cfg("vpn.extraWireGuard", ""), cfg("vpn.olcRTC", "")
		if key == "vpn.olcRTC" {
			olc = value
		} else {
			wg = value
		}
		exits, err := configuredTunnelExits(wg, olc)
		if err != nil {
			return err
		}
		names := make([]string, 0, len(exits))
		for _, exit := range exits {
			if exit.olcRTC == (key == "vpn.olcRTC") {
				names = append(names, exit.iface)
			}
		}
		return setCfg(key, strings.Join(names, ","))
	}
	if key == "net.qualityIP" {
		value = strings.TrimSpace(value)
		if !validQualityIP(value) {
			return fmt.Errorf("нужен IPv4-адрес одного узла для ICMP-измерений")
		}
		return setCfg(key, value)
	}
	if key == "net.qualityEnabled" {
		if value != "true" && value != "false" {
			return fmt.Errorf("нужно true или false")
		}
		return setCfg(key, value)
	}
	if key == "net.localNetworks" || key == "net.pinFlows" {
		return setNetworkPolicy(key, value)
	}
	return m.base.Set(key, value)
}
func (m *inet) Checks() []Check {
	val := func(cmd string, a ...string) string { o, _ := run(cmd, a...); return strings.TrimSpace(o) }
	return []Check{
		{ID: "sys.inet", Title: "Интернет провайдера доступен",
			Run: func() Finding {
				return Finding{OK: probe(wanIface(), "https://1.1.1.1"), Text: "напрямую через " + wanIface(), Hint: "Проверьте кабель, роутер и баланс у провайдера. Туннели без него не поднимутся"}
			}},
		{ID: "sys.forward", Title: "Пересылка пакетов включена", FixTitle: "Включить",
			Run: func() Finding {
				return Finding{OK: val("sysctl", "-n", "net.ipv4.ip_forward") == "1", Text: "net.ipv4.ip_forward", Hint: "Без неё клиенты WG-Server не получат интернет"}
			},
			Fix: func() (string, error) {
				run("sysctl", "-w", "net.ipv4.ip_forward=1")
				return "пересылка включена", nil
			}},
		{ID: "sys.time", Title: "Часы синхронизированы", FixTitle: "Включить синхронизацию",
			Run: func() Finding {
				return Finding{OK: val("timedatectl", "show", "-p", "NTPSynchronized", "--value") == "yes", Text: "timedatectl", Hint: "При неверном времени не проходят TLS и рукопожатия"}
			},
			Fix: func() (string, error) {
				run("timedatectl", "set-ntp", "true")
				return "синхронизация включена", nil
			}},
		{ID: "sys.disk", Title: "На диске есть место",
			Run: func() Finding {
				f := strings.Fields(val("df", "--output=pcent", "/"))
				p := ""
				if len(f) > 0 {
					p = f[len(f)-1]
				}
				return Finding{OK: len(p) < 3 || p < "90%", Text: "занято " + p, Hint: "Очистите журналы: journalctl --vacuum-size=200M"}
			}},
	}
}

type direct struct{ base }

func (m *direct) ID() string    { return "direct" }
func (m *direct) Name() string  { return "Напрямую" }
func (m *direct) Color() string { return "#9fb3c8" }
func (m *direct) Order() int    { return 40 }
func (m *direct) Tick()         {}

// Состояние «Напрямую» — это состояние интернета провайдера, читается каждый раз заново.
func (m *direct) Status() Status {
	if mod("inet").Status().Up {
		return Status{Level: 0, Up: true, State: "через провайдера"}
	}
	return Status{Level: 2, State: "провайдер не отвечает"}
}
func (m *direct) Exit() *Exit { return &Exit{Iface: wanIface(), Table: 0, Mark: 0x14} }

type block struct{ base }

func (m *block) ID() string    { return "block" }
func (m *block) Name() string  { return "Заблокировать" }
func (m *block) Color() string { return "#ff4d5e" }
func (m *block) Order() int    { return 45 }
func (m *block) Tick()         { m.setSt(0, true, "трафик отбрасывается", "") }
func (m *block) Exit() *Exit   { return &Exit{Block: true, Mark: 0x1f} }
