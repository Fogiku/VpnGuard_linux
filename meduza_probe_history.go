package main

import (
	"strconv"
	"time"
)

const meduzaProbeHistoryLimit = 32

type meduzaProbeSeries struct {
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
	Protocol  string    `json:"protocol"`
	Up        bool      `json:"up"`
	Secondary bool      `json:"secondary"`
	Count     int       `json:"count"`
}

func (m *meduza) recordProbe(at time.Time, protocol string, up, secondary bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.probeHistory)
	if n > 0 && !m.startProbeSeries {
		last := &m.probeHistory[n-1]
		if last.Protocol == protocol && last.Up == up && last.Secondary == secondary {
			last.Last = at
			last.Count++
			return
		}
	}
	m.startProbeSeries = false
	if n == meduzaProbeHistoryLimit {
		copy(m.probeHistory, m.probeHistory[1:])
		m.probeHistory = m.probeHistory[:n-1]
	}
	m.probeHistory = append(m.probeHistory, meduzaProbeSeries{First: at, Last: at, Protocol: protocol, Up: up, Secondary: secondary, Count: 1})
}

func (m *meduza) probeHistoryTable() Table {
	t := Table{ID: "meduza-probe-history", Title: "История HTTPS-проверок туннеля", Cols: []string{"Первая проверка", "Последняя проверка", "Протокол", "Основная цель", "Вторая цель", "Проверок"},
		Empty: "Агент ещё не проверял подключённый туннель.",
		Note:  "До 32 последних серий, новые сверху. Объединяются последовательные фоновые проверки с одинаковым протоколом и результатом. Время указано на шлюзе."}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.probeHistory) - 1; i >= 0; i-- {
		s := m.probeHistory[i]
		primary, secondary := "Ответила", "Не проверялась"
		if s.Secondary {
			t.ProblemRows = append(t.ProblemRows, len(t.Rows))
			primary, secondary = "Нет ответа", "Нет ответа"
			if s.Up {
				secondary = "Ответила"
			}
		}
		const layout = "02.01.2006 15:04:05"
		t.Rows = append(t.Rows, []string{s.First.Format(layout), s.Last.Format(layout), orDash(s.Protocol), primary, secondary, strconv.Itoa(s.Count)})
	}
	return t
}

func (m *meduza) restoreProbeHistory(saved []meduzaProbeSeries) {
	if len(saved) > meduzaProbeHistoryLimit {
		saved = saved[len(saved)-meduzaProbeHistoryLimit:]
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.probeHistory = nil
	for _, s := range saved {
		if s.Count > 0 && !s.First.IsZero() && !s.Last.Before(s.First) && len(s.Protocol) <= 128 && (s.Up || s.Secondary) {
			m.probeHistory = append(m.probeHistory, s)
		}
	}
	m.startProbeSeries = len(m.probeHistory) > 0
}
