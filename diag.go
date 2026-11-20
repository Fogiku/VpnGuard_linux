// Диагностика и мониторинг. Проверки собираются со всех модулей; у каждой есть понятная причина и, где возможно,
// кнопка исправления. История метрик хранится час с шагом 5 секунд.
package main

import (
	"errors"
	"sync"
	"time"
)

type CheckRes struct {
	ID       string `json:"id"`
	Module   string `json:"module"`
	Title    string `json:"title"`
	FixTitle string `json:"fixTitle,omitempty"`
	OK       bool   `json:"ok"`
	Text     string `json:"text"`
	Hint     string `json:"hint,omitempty"`
	At       string `json:"at"`
}

var (
	diagMu  sync.Mutex
	diagRes []CheckRes
)

func runChecks() []CheckRes {
	var out []CheckRes
	for _, m := range Mods {
		if m.Status().Level == -1 {
			continue
		}
		for _, c := range m.Checks() {
			f := c.Run()
			r := CheckRes{ID: c.ID, Module: m.Name(), Title: c.Title, OK: f.OK, Text: f.Text, At: time.Now().Format("15:04:05")}
			if !f.OK {
				r.Hint = f.Hint
				if c.Fix != nil {
					r.FixTitle = c.FixTitle
				}
			}
			out = append(out, r)
		}
	}
	diagMu.Lock()
	diagRes = out
	diagMu.Unlock()
	return out
}
func fixCheck(id string) (string, error) {
	for _, m := range Mods {
		for _, c := range m.Checks() {
			if c.ID == id {
				if c.Fix == nil {
					return "", errors.New("эта проблема не исправляется автоматически")
				}
				msg, err := c.Fix()
				if err == nil {
					Decide("INFO", "Диагностика: «%s» → %s", c.Title, msg)
					go m.Tick()
				}
				return msg, err
			}
		}
	}
	return "", errors.New("проверка не найдена")
}
func startDiag() {
	startNetworkTelemetry()
	go func() {
		time.Sleep(4 * time.Second)
		for {
			runChecks()
			time.Sleep(60 * time.Second)
		}
	}()
	go func() {
		for tick := 1; ; tick++ {
			time.Sleep(5 * time.Second)
			collectHistory()
			if tick%6 == 0 {
				_ = telemetry.flush(time.Now().Unix())
			}
		}
	}()
}
