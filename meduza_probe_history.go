package main

import (
	"strconv"
	"time"
)

const meduzaProbeHistoryLimit = 32

type meduzaProbeSeries struct {
	first, last time.Time
	protocol    string
	up          bool
	secondary   bool
	count       int
}

func (m *meduza) recordProbe(at time.Time, protocol string, up, secondary bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.probeHistory)
	if n > 0 {
		last := &m.probeHistory[n-1]
		if last.protocol == protocol && last.up == up && last.secondary == secondary {
			last.last = at
			last.count++
			return
		}
	}
	if n == meduzaProbeHistoryLimit {
		copy(m.probeHistory, m.probeHistory[1:])
		m.probeHistory = m.probeHistory[:n-1]
	}
	m.probeHistory = append(m.probeHistory, meduzaProbeSeries{first: at, last: at, protocol: protocol, up: up, secondary: secondary, count: 1})
}

func (m *meduza) probeHistoryTable() Table {
	t := Table{Title: "История HTTPS-проверок туннеля", Cols: []string{"Первая проверка", "Последняя проверка", "Протокол", "Основная цель", "Вторая цель", "Проверок"},
		Empty: "Агент ещё не проверял подключённый туннель.",
		Note:  "До 32 последних серий с момента запуска агента, новые сверху. Объединяются последовательные фоновые проверки с одинаковым протоколом и результатом. Время указано на шлюзе."}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.probeHistory) - 1; i >= 0; i-- {
		s := m.probeHistory[i]
		primary, secondary := "Ответила", "Не проверялась"
		if s.secondary {
			primary, secondary = "Нет ответа", "Нет ответа"
			if s.up {
				secondary = "Ответила"
			}
		}
		const layout = "02.01.2006 15:04:05"
		t.Rows = append(t.Rows, []string{s.first.Format(layout), s.last.Format(layout), orDash(s.protocol), primary, secondary, strconv.Itoa(s.count)})
	}
	return t
}
