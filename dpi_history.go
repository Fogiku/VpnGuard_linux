package main

import (
	"strconv"
	"time"
)

const dpiHistoryLimit = 16

type dpiSampleCounts struct {
	Packets    int `json:"packets"`
	Recognized int `json:"recognized"`
	Unknown    int `json:"unknown"`
	Bound      int `json:"bound"`
}

type dpiSampleResult struct {
	Description string           `json:"description"`
	At          int64            `json:"at"`
	Status      string           `json:"status"`
	Counts      *dpiSampleCounts `json:"counts,omitempty"`
}

// Only these fixed status descriptions and numeric aggregates leave the gateway.
var dpiStatuses = map[string]string{
	"simulation": "Имитация", "worker": "Сборщик недоступен", "missing": "ndpiReader отсутствует",
	"version": "Несовместимая версия nDPI", "permission": "Недостаточно прав", "interface": "Ошибка доступа к интерфейсу или памяти",
	"drops": "Потеря пакетов при захвате", "format": "Ошибка формата выборки", "reader": "Ошибка nDPI",
	"empty": "Нет пакетов IPv4 TCP/UDP", "sample": "Обработано",
}

type dpiHistoryPage struct {
	SchemaVersion int               `json:"schemaVersion"`
	Enabled       bool              `json:"enabled"`
	Samples       []dpiSampleResult `json:"samples"`
}

func (m *flowModule) diagnosticDPI() dpiHistoryPage {
	m.mu.Lock()
	defer m.mu.Unlock()
	page := dpiHistoryPage{SchemaVersion: 1, Enabled: cfgBool("flows.enabled", false) && cfgBool("flows.dpiEnabled", false), Samples: []dpiSampleResult{}}
	if page.Enabled {
		page.Samples = append(page.Samples, m.dpiHistory...)
	}
	return page
}

func dpiHistoryTable(samples []dpiSampleResult) Table {
	t := Table{Title: "История выборок nDPI", Cols: []string{"Время", "Результат", "Пакетов", "Распознано", "Unknown", "Связано с conntrack"}, Note: "Последние 16 попыток. Счётчики потоков относятся к одной выборке.", Rows: [][]string{}}
	for i := len(samples) - 1; i >= 0; i-- {
		s := samples[i]
		row := []string{time.Unix(s.At, 0).Format(time.RFC3339), s.Description}
		if c := s.Counts; c != nil {
			row = append(row, strconv.Itoa(c.Packets), strconv.Itoa(c.Recognized), strconv.Itoa(c.Unknown), strconv.Itoa(c.Bound))
		} else {
			row = append(row, "—", "—", "—", "—")
		}
		t.Rows = append(t.Rows, row)
	}
	return t
}
