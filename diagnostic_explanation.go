package main

import "fmt"

type diagnosticExplanationV1 struct {
	SchemaVersion int      `json:"schemaVersion"`
	Simulation    bool     `json:"simulation"`
	Summary       string   `json:"summary"`
	Observations  []string `json:"observations"`
}

func explainDiagnosticSnapshot(s diagnosticSnapshotV1) diagnosticExplanationV1 {
	e := diagnosticExplanationV1{SchemaVersion: 1, Simulation: s.Simulation, Observations: []string{}}
	if !s.RoutingReady {
		e.Observations = append(e.Observations, "Агент ещё не подтвердил готовность маршрутизации.")
	}
	active := 0
	for _, m := range s.Modules {
		var status string
		switch m.Level {
		case -1:
			continue
		case 0:
			active++
			continue
		case 1:
			status = "предупреждение"
		case 2:
			status = "сбой"
		default:
			status = "неизвестный уровень состояния"
		}
		e.Observations = append(e.Observations, fmt.Sprintf("%s сообщает: %s (level=%d, up=%t).", m.ID, status, m.Level, m.Up))
	}
	switch {
	case len(e.Observations) > 0:
		e.Summary = "В снимке есть отклонения. Для выяснения причины нужны результаты проверок."
	case active == 0:
		e.Summary = "Недостаточно данных: в снимке нет состояний активных модулей."
	default:
		e.Summary = "Маршрутизация готова. Активные модули в снимке сообщают штатное состояние."
	}
	if s.Decisions.Warning+s.Decisions.Error > 0 {
		e.Observations = append(e.Observations, fmt.Sprintf("В журнале решений предупреждений — %d, ошибок — %d. Снимок не указывает их время и модуль.", s.Decisions.Warning, s.Decisions.Error))
	}
	return e
}
