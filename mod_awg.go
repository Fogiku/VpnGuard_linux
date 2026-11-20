// Модуль AmneziaWG: туннели awg-quick@<имя> из /etc/amnezia/amneziawg. Загрузка, просмотр, выбор и удаление
// конфигураций через веб, слежение за рукопожатием и трафиком, перезапуск и переход на другую конфигурацию.
package main

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type awg struct {
	base
	fails int
	hsAge int64
	rx    rate
	view  string
}

func init()                  { Register(&awg{}) }
func (m *awg) ID() string    { return "awg" }
func (m *awg) Name() string  { return "AmneziaWG" }
func (m *awg) Color() string { return "#9d8cff" }
func (m *awg) Order() int    { return 20 }
func (m *awg) dir() string   { return cfg("awg.dir", "/etc/amnezia/amneziawg") }
func (m *awg) name() string  { return cfg("awg.active", "awg0") }
func (m *awg) unit() string  { return "awg-quick@" + m.name() }
func (m *awg) configs() []string {
	var out []string
	for _, f := range S.List(m.dir()) {
		if strings.HasSuffix(f, ".conf") {
			out = append(out, strings.TrimSuffix(f, ".conf"))
		}
	}
	return out
}
func (m *awg) ok() bool { return probe(m.name(), cfg("vpn.probeUrl", "https://1.1.1.1")) }
func (m *awg) Tick() {
	m.tk.Lock()
	defer m.tk.Unlock()
	if cfg("awg.enabled", "true") != "true" {
		m.setSt(-1, false, "Выключен", "модуль отключён в настройках")
		return
	}
	n := m.name()
	if _, err := S.ReadFile(m.dir() + "/" + n + ".conf"); err != nil {
		m.setSt(2, false, "Нет конфигурации", "Загрузите конфигурацию AmneziaWG на этой странице")
		return
	}
	if !active(m.unit()) {
		if allow("awg.start", 5, 30*time.Minute) {
			run("systemctl", "start", m.unit())
			Decide("WARN", "AmneziaWG: туннель %s не запущен → запуск", n)
		}
	}
	m.hsAge = -1
	if out, c := run("awg", "show", n, "latest-handshakes"); c == 0 {
		if f := strings.Fields(out); len(f) >= 2 {
			if t, _ := strconv.ParseInt(f[1], 10, 64); t > 0 {
				m.hsAge = time.Now().Unix() - t
			}
		}
	}
	if out, c := run("awg", "show", n, "transfer"); c == 0 {
		if f := strings.Fields(out); len(f) >= 2 {
			v, _ := strconv.ParseFloat(f[1], 64)
			m.metric("rx", m.rx.bps(v))
		}
	}
	hs := "нет"
	if m.hsAge >= 0 {
		hs = fmt.Sprintf("%d с назад", m.hsAge)
	}
	kv := [][2]string{{"Конфигурация", n}, {"Рукопожатие", hs}, {"Служба", m.unit()}}
	if m.ok() {
		if m.fails > 0 {
			Decide("INFO", "AmneziaWG: трафик снова проходит (%s)", n)
		}
		m.fails = 0
		m.setSt(0, true, "Подключено", "", kv...)
		return
	}
	m.fails++
	why := "проверка через " + n + " не проходит"
	if m.hsAge < 0 || m.hsAge > 180 {
		why = "сервер не отвечает на рукопожатие: недоступен или блокируется провайдером"
	}
	m.setSt(2, false, "Нет трафика", why, kv...)
	need := cfgInt("awg.failChecks", 2)
	if m.fails == need && allow("awg.restart", 5, 30*time.Minute) {
		Decide("WARN", "AmneziaWG: трафик не проходит %d проверки подряд → перезапуск туннеля %s", m.fails, n)
		run("systemctl", "restart", m.unit())
	} else if m.fails == need+1 && cfgBool("awg.autoSwitch", true) {
		for _, c := range m.configs() {
			if c == n {
				continue
			}
			run("systemctl", "stop", m.unit())
			setCfg("awg.active", c)
			run("systemctl", "start", m.unit())
			if m.ok() {
				Decide("WARN", "AmneziaWG: %s не отвечает → переключено на конфигурацию %s", n, c)
				m.fails = 0
				Emit("routes.changed", "awg")
				return
			}
		}
		run("systemctl", "stop", m.unit())
		setCfg("awg.active", n)
		run("systemctl", "start", m.unit())
		Decide("ERROR", "AmneziaWG: ни одна конфигурация не пропускает трафик")
	}
}
func (m *awg) Exit() *Exit { return &Exit{Iface: m.name(), Table: 102, Mark: 0x12} }
func (m *awg) Fields() []Field {
	var o []Opt
	for _, c := range m.configs() {
		o = append(o, Opt{c, c})
	}
	return []Field{fb("awg.enabled", "Модуль включён", "bool", "true", ""),
		fb("awg.active", "Активная конфигурация", "select", "awg0", "", o...),
		fb("awg.autoSwitch", "Переходить на другую конфигурацию при сбое", "bool", "true", ""),
		fb("awg.failChecks", "Неудачных проверок до восстановления", "number", "2", "")}
}
func (m *awg) Set(k, v string) error {
	if k == "awg.active" && v != m.name() {
		run("systemctl", "stop", m.unit())
		setCfg(k, v)
		run("systemctl", "start", m.unit())
		Emit("routes.changed", "awg")
		go m.Tick()
		return nil
	}
	setCfg(k, v)
	go m.Tick()
	return nil
}

var reAwgName = regexp.MustCompile(`^[a-z0-9_-]{1,15}$`)

// normalizeAwg проверяет конфигурацию и добавляет Table = off: маршрутами управляет VpnGuard, а не awg-quick.
func normalizeAwg(text string) (string, error) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	for _, need := range []string{"[Interface]", "[Peer]", "PrivateKey", "PublicKey", "Endpoint"} {
		if !strings.Contains(text, need) {
			return "", errors.New("в конфигурации нет «" + need + "»")
		}
	}
	if confVal(text, "Table") == "" {
		text = strings.Replace(text, "[Interface]", "[Interface]\nTable = off", 1)
	}
	return strings.TrimSpace(text) + "\n", nil
}
func (m *awg) Actions() []Action {
	return []Action{
		{ID: "add", Title: "Загрузить конфигурацию", Args: []Field{{Key: "name", Title: "Имя (латиница, до 15 знаков)", Type: "text"}, {Key: "text", Title: "Текст файла .conf", Type: "textarea"}}},
		{ID: "restart", Title: "Перезапустить туннель", Confirm: "Клиенты на этом выходе на несколько секунд потеряют связь. Перезапустить?"},
		{ID: "stop", Title: "Остановить", Danger: true, Confirm: "Остановить туннель AmneziaWG и выключить модуль?"},
	}
}
func (m *awg) Do(id string, a map[string]string) (string, error) {
	row := a["row"]
	path := func(n string) string { return m.dir() + "/" + n + ".conf" }
	switch id {
	case "add":
		if !reAwgName.MatchString(a["name"]) {
			return "", errors.New("имя: только строчная латиница, цифры, - и _, до 15 знаков")
		}
		t, err := normalizeAwg(a["text"])
		if err != nil {
			return "", err
		}
		if err := S.WriteFile(path(a["name"]), t, 0o600); err != nil {
			return "", err
		}
		return "Конфигурация " + a["name"] + " сохранена", nil
	case "restart":
		run("systemctl", "restart", m.unit())
		go m.Tick()
		return "Туннель перезапущен", nil
	case "stop":
		run("systemctl", "stop", m.unit())
		setCfg("awg.enabled", "false")
		go m.Tick()
		return "Туннель остановлен, модуль выключен", nil
	case "activate":
		return "Активна конфигурация " + row, m.Set("awg.active", row)
	case "view":
		t, err := S.ReadFile(path(row))
		if err != nil {
			return "", err
		}
		m.view = row + ".conf\n\n" + regexp.MustCompile(`(?m)^(\s*(PrivateKey|PresharedKey)\s*=\s*).+$`).ReplaceAllString(t, "${1}(скрыто)")
		return "Конфигурация показана ниже, ключи скрыты", nil
	case "delete":
		if row == m.name() {
			return "", errors.New("нельзя удалить активную конфигурацию — сначала выберите другую")
		}
		return "Конфигурация " + row + " удалена", S.Remove(path(row))
	}
	return "", errors.New("неизвестное действие")
}
func (m *awg) Tables() []Table {
	var rows [][]string
	for _, c := range m.configs() {
		t, _ := S.ReadFile(m.dir() + "/" + c + ".conf")
		st := "в запасе"
		if c == m.name() {
			st = "активна"
		}
		rows = append(rows, []string{c, confVal(t, "Endpoint"), confVal(t, "Address"), st})
	}
	out := []Table{{Title: "Конфигурации", Cols: []string{"Имя", "Сервер", "Адрес", "Состояние"}, Rows: rows, Empty: "Конфигураций нет — загрузите файл .conf",
		Actions: []Action{{ID: "activate", Title: "Сделать активной"}, {ID: "view", Title: "Показать"}, {ID: "delete", Title: "Удалить", Danger: true, Confirm: "Удалить конфигурацию?"}}}}
	if m.view != "" {
		out = append(out, Table{Title: "Просмотр", Text: m.view})
	}
	return out
}
func (m *awg) Checks() []Check {
	return []Check{
		{ID: "awg.unit", Title: "Туннель AmneziaWG запущен", FixTitle: "Запустить",
			Run: func() Finding {
				return Finding{OK: active(m.unit()), Text: m.unit(), Hint: "Если не запускается — проверьте модуль ядра amneziawg: он пересобирается при обновлении ядра"}
			},
			Fix: func() (string, error) {
				run("systemctl", "restart", m.unit())
				return "туннель перезапущен", nil
			}},
		{ID: "awg.handshake", Title: "Сервер отвечает на рукопожатие",
			Run: func() Finding {
				return Finding{OK: m.hsAge >= 0 && m.hsAge < 180, Text: fmt.Sprintf("последнее %d с назад", m.hsAge), Hint: "Сервер недоступен, сменил ключи или блокируется. Проверьте сервер или загрузите другую конфигурацию"}
			}},
		{ID: "awg.traffic", Title: "Трафик проходит через туннель",
			Run: func() Finding { return Finding{OK: m.ok(), Text: "HTTPS-запрос через " + m.name()} }},
		{ID: "awg.table", Title: "В конфигурации стоит Table = off", FixTitle: "Исправить конфигурацию",
			Run: func() Finding {
				t, _ := S.ReadFile(m.dir() + "/" + m.name() + ".conf")
				return Finding{OK: strings.EqualFold(confVal(t, "Table"), "off"), Text: m.name() + ".conf", Hint: "Без этой строки awg-quick заберёт себе весь трафик шлюза в обход правил"}
			},
			Fix: func() (string, error) {
				p := m.dir() + "/" + m.name() + ".conf"
				t, _ := S.ReadFile(p)
				n, err := normalizeAwg(t)
				if err != nil {
					return "", err
				}
				_ = S.WriteFile(p, n, 0o600)
				run("systemctl", "restart", m.unit())
				return "строка добавлена, туннель перезапущен", nil
			}},
	}
}
