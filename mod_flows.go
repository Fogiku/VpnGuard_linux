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
	SeenReply       *bool   `json:"seenReply,omitempty"`
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
	dpiHistory    []dpiSampleResult
	bindings      map[string]dpiBinding
	installMu     sync.Mutex
	installStatus string
	base
	profileArgs string
	unanswered  map[dpiRowKey]bool
	rows        []flowRow
	at          time.Time
	truncated   bool
	dpi         *Table
	events      *flowEventSession
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
	var result dpiSampleResult
	var bindings map[string]dpiBinding
	if cfgBool("flows.enabled", false) && cfgBool("flows.dpiEnabled", false) {
		sample, summary, matched := sampleDPITable(wgMod.iface(), m.events)
		result = summary
		result.Description = dpiStatuses[result.Status]
		bindings = matched
		dpi = &sample
	}
	var view struct {
		Rows      []flowRow `json:"rows"`
		Truncated bool      `json:"truncated"`
	}
	var at time.Time
	profileArgs := ""
	level, status, why := -1, "Выключен", "Снимки потоков не собираются"
	if cfgBool("flows.enabled", false) {
		if Sim {
			level, status, why = 1, "Имитация", "Реальный conntrack в имитации не читается"
		} else {
			if cfgBool("zapret.passiveDraft", false) {
				profileArgs, _ = S.ReadFile(zArgs)
			}
			output, code := S.Run(3*time.Second, flowSnapshotScript, "python3", "-")
			if code != 0 || json.Unmarshal([]byte(output), &view) != nil || len(view.Rows) > 512 {
				level, status, why = 1, "Нет снимка", "Не удалось прочитать conntrack; нужны Python 3 и CAP_NET_ADMIN."
				view.Rows, view.Truncated = nil, false
			} else {
				at = time.Now()
				count := len(view.Rows)
				result.SnapshotRows, result.Truncated = &count, view.Truncated
				level, status, why = 0, "Снимок соединений", "IPv4 TCP/UDP. Метка nDPI появляется при подтверждённой привязке к поколению соединения."
				if view.Truncated {
					level = 1
					why += " Достигнут лимит 512 записей; снимок неполный."
				}
			}
		}
	}
	m.mu.Lock()
	stableProfile := profileArgs != "" && profileArgs == m.profileArgs
	m.profileArgs = profileArgs
	m.unanswered = repeatedUnanswered(m.rows, view.Rows, !m.truncated && !view.Truncated && !m.at.IsZero() && at.After(m.at) && at.Sub(m.at) <= time.Minute)
	m.rows, m.at, m.truncated = view.Rows, at, view.Truncated
	m.bindings, m.dpi = bindings, dpi
	if dpi == nil {
		m.dpiHistory = nil
	} else {
		if len(m.dpiHistory) == dpiHistoryLimit {
			m.dpiHistory = m.dpiHistory[1:]
		}
		m.dpiHistory = append(m.dpiHistory, result)
	}
	m.mu.Unlock()
	m.setSt(level, false, status, why)
	if stableProfile {
		m.maybeDraftFromPending(profileArgs)
	}
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

func flowPinLabel(mark uint32, resources []routeResource) string {
	pin := (mark >> 16) & 0xff
	if pin == 0 {
		return "—"
	}
	for _, r := range resources {
		if r.Mark == pin {
			return r.Owner
		}
	}
	return fmt.Sprintf("0x%02x", pin)
}

func (m *flowModule) Tables() []Table {
	m.mu.Lock()
	defer m.mu.Unlock()
	labels := m.snapshotLabels()
	rows := [][]string{}
	fixedResources := legacyRouteResources()
	for i, r := range m.rows {
		id := "нет ID"
		app, observedAt := "Нет привязки", "—"
		if r.ConntrackID != nil {
			if observation, ok := labels[dpiKey(r)]; ok {
				app = observation.Flow.Application
				observedAt = observation.Last.Format(time.RFC3339Nano)
			}
			id = strconv.FormatUint(uint64(*r.ConntrackID), 10)
		}
		signal := "—"
		if r.ConntrackID != nil && m.unanswered[dpiKey(r)] {
			signal = "Нет ответа в двух снимках"
		}
		rows = append(rows, []string{strconv.Itoa(i), r.Protocol, fmt.Sprintf("%s:%d", r.Source, r.SourcePort), fmt.Sprintf("%s:%d", r.Destination, r.DestinationPort), fmt.Sprintf("0x%08x", r.Mark), app, id, strconv.Itoa(int(r.Zone)), observedAt, flowPinLabel(r.Mark, fixedResources), signal})
	}
	note := "Метка nDPI относится к последней выборке и подтверждённому поколению conntrack. Unknown означает, что nDPI обработал поток и вернул Unknown. Для привязки включите наблюдение жизненного цикла и сбор nDPI. Маршруты не изменяются."
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
	tables := []Table{{Title: "Соединения IPv4", Cols: []string{"ID", "Протокол", "Источник", "Назначение", "ct mark", "Метка nDPI", "Conntrack ID", "Zone", "Наблюдение nDPI", "Закрепление (биты 16–23)", "Наблюдение zapret"}, Rows: rows, Empty: "Нет снимка", Note: note + " Для дополнительных выходов показан код закрепления. Фактический интерфейс пакета проверяется отдельно. Conntrack ID может повторно использоваться; он не доказывает непрерывность соединения между снимками."}}
	if m.dpi != nil {
		tables = append(tables, *m.dpi, dpiHistoryTable(m.dpiHistory))
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
