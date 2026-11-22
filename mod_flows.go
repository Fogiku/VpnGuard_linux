package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"
)

//go:embed deploy/flow_snapshot.py
var flowSnapshotScript string

type flowRow struct {
	Protocol        string  `json:"protocol"`
	Source          string  `json:"source"`
	Destination     string  `json:"destination"`
	SourcePort      int     `json:"sourcePort"`
	DestinationPort int     `json:"destinationPort"`
	Mark            uint32  `json:"mark"`
	Application     string  `json:"application"`
	ConntrackID     *uint32 `json:"conntrackId"`
	Zone            uint16  `json:"zone"`
}
type flowModule struct {
	bindings      map[string]dpiBinding
	installMu     sync.Mutex
	installStatus string
	base
	rows      []flowRow
	at        time.Time
	truncated bool
	dpi       *Table
	events    *flowEventSession
}

var flowsMod = &flowModule{}

func init()                                 { Register(flowsMod) }
func (m *flowModule) ID() string            { return "flows" }
func (m *flowModule) Name() string          { return "Потоки" }
func (m *flowModule) Color() string         { return "#49b8e8" }
func (m *flowModule) Aux() bool             { return true }
func (m *flowModule) Period() time.Duration { return 15 * time.Second }
func (m *flowModule) Fields() []Field {
	return []Field{{Key: "flows.enabled", Title: "Собирать снимки соединений", Type: "bool", Value: cfg("flows.enabled", "false"), Help: "Чтение conntrack IPv4 раз в 15 секунд, до 512 записей. Адреса хранятся только в памяти. Распознавание nDPI включается отдельно."}, {Key: "flows.eventsEnabled", Title: "Наблюдать жизненный цикл соединений", Type: "bool", Value: cfg("flows.eventsEnabled", "false"), Help: "Нужен включённый сбор снимков. Подписка NEW/UPDATE/DESTROY, до 512 поколений в памяти. Потеря heartbeat сбрасывает поколения. Наблюдение требуется для привязки меток nDPI к отдельным соединениям."}, {Key: "flows.dpiEnabled", Title: "Пассивное распознавание nDPI", Type: "bool", Value: cfg("flows.dpiEnabled", "false"), Help: "Короткие выборки IPv4 TCP/UDP на интерфейсе WG-Server. Нужны сбор снимков, Python 3 и ndpiReader 4.2.0."}}
}
func (m *flowModule) Set(k, v string) error {
	if k != "flows.enabled" && k != "flows.eventsEnabled" && k != "flows.dpiEnabled" {
		return errNoField
	}
	if v != "true" && v != "false" {
		return fmt.Errorf("нужно true или false")
	}
	if err := setCfg(k, v); err != nil {
		return err
	}
	m.Tick()
	return nil
}
func (m *flowModule) Tick() {
	m.tk.Lock()
	defer m.tk.Unlock()
	m.syncEvents()
	var dpi *Table
	var bindings map[string]dpiBinding
	if cfgBool("flows.enabled", false) && cfgBool("flows.dpiEnabled", false) {
		sample, matched := sampleDPITable(wgMod.iface(), m.events)
		bindings = matched
		dpi = &sample
	}
	m.mu.Lock()
	m.dpi = dpi
	m.bindings = nil
	m.mu.Unlock()
	if !cfgBool("flows.enabled", false) {
		m.mu.Lock()
		m.rows = nil
		m.at = time.Time{}
		m.mu.Unlock()
		m.setSt(-1, false, "Выключен", "Снимки потоков не собираются")
		return
	}
	if Sim {
		m.mu.Lock()
		m.rows = nil
		m.at = time.Time{}
		m.mu.Unlock()
		m.setSt(1, false, "Имитация", "Реальный conntrack в имитации не читается")
		return
	}
	output, code := S.Run(3*time.Second, flowSnapshotScript, "python3", "-")
	var view struct {
		Rows      []flowRow `json:"rows"`
		Seen      int       `json:"seen"`
		Truncated bool      `json:"truncated"`
	}
	if code != 0 || json.Unmarshal([]byte(output), &view) != nil || len(view.Rows) > 512 {
		m.mu.Lock()
		m.rows = nil
		m.at = time.Time{}
		m.mu.Unlock()
		m.setSt(1, false, "Нет снимка", "Не удалось прочитать conntrack; нужны Python 3 и CAP_NET_ADMIN. Старые данные удалены.")
		return
	}
	m.mu.Lock()
	m.rows = view.Rows
	m.bindings = bindings
	m.truncated = view.Truncated
	m.at = time.Now()
	m.mu.Unlock()
	why := "IPv4 TCP/UDP. При недостатке данных приложение указано как Unknown. Это снимок таблицы ядра, не история и не измерение скорости."
	level := 0
	if view.Truncated {
		level = 1
		why += " Достигнут лимит 512 записей; снимок неполный."
	}
	m.setSt(level, false, "Снимок соединений", why)
}

type flowCounts struct {
	At        int64 `json:"at"`
	TCP       int   `json:"tcp"`
	UDP       int   `json:"udp"`
	Truncated bool  `json:"truncated"`
}

func (m *flowModule) snapshotCounts() *flowCounts {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.at.IsZero() {
		return nil
	}
	counts := &flowCounts{At: m.at.Unix(), Truncated: m.truncated}
	for _, row := range m.rows {
		switch row.Protocol {
		case "tcp":
			counts.TCP++
		case "udp":
			counts.UDP++
		}
	}
	return counts
}

func (m *flowModule) lifecycle() *lifecycleSummary {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.events.summary()
}

func (m *flowModule) Tables() []Table {
	m.mu.Lock()
	defer m.mu.Unlock()
	labels := m.snapshotLabels()
	rows := [][]string{}
	for i, r := range m.rows {
		id := "нет ID"
		app, observedAt := "Unknown", "—"
		if r.ConntrackID != nil {
			if observation, ok := labels[dpiKey(r)]; ok {
				app = observation.Flow.Application
				observedAt = observation.Last.Format(time.RFC3339Nano)
			}
			id = strconv.FormatUint(uint64(*r.ConntrackID), 10)
		}
		rows = append(rows, []string{strconv.Itoa(i), r.Protocol, fmt.Sprintf("%s:%d", r.Source, r.SourcePort), fmt.Sprintf("%s:%d", r.Destination, r.DestinationPort), fmt.Sprintf("0x%08x", r.Mark), app, id, strconv.Itoa(int(r.Zone)), observedAt})
	}
	note := "Метка nDPI относится к последней выборке и подтверждённому поколению conntrack. Порт 443 не доказывает HTTPS/QUIC; ECH и приложения не определяются. Маршруты не изменяются."
	if !m.at.IsZero() {
		note += " Снимок: " + m.at.Format(time.RFC3339)
	}
	if m.events != nil {
		if summary := m.events.summary(); summary != nil {
			note += fmt.Sprintf(" С начала подписки открыто %d, завершено %d, отслеживается %d. Без наблюдаемого начала: UPDATE %d, DESTROY %d.", summary.Opened, summary.Completed, summary.Active, summary.UnmatchedUpdates, summary.UnmatchedDestroys)
		} else {
			note += " Нет свежих данных подписки на события."
		}
	}
	tables := []Table{{Title: "Соединения IPv4", Cols: []string{"ID", "Протокол", "Источник", "Назначение", "ct mark", "Приложение", "Conntrack ID", "Zone", "Наблюдение nDPI"}, Rows: rows, Empty: "Нет снимка", Note: note + " Conntrack ID может повторно использоваться; он не доказывает непрерывность соединения между снимками."}}
	if m.dpi != nil {
		tables = append(tables, *m.dpi)
	}
	if m.installStatus != "" {
		tables = append(tables, Table{Title: "Установка nDPI", Text: m.installStatus})
	}
	return tables
}

func (m *flowModule) syncEvents() {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := !Sim && cfgBool("flows.enabled", false) && cfgBool("flows.eventsEnabled", false)
	if m.events != nil {
		select {
		case <-m.events.done:
			m.events = nil
		default:
		}
	}
	if !want && m.events != nil {
		m.events.stop()
		m.events = nil
	}
	if want && m.events == nil {
		if runner, ok := S.(flowEventRunner); ok {
			m.events = startFlowEvents(runner)
		}
	}
}
