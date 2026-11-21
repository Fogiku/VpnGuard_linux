package main

import (
	"testing"
	"time"
)

func TestMeduzaProbeHistory(t *testing.T) {
	m := &meduza{}
	at := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	m.recordProbe(at, "ultra", true, false)
	m.recordProbe(at.Add(time.Minute), "ultra", true, false)
	m.recordProbe(at.Add(2*time.Minute), "ultra", true, true)
	m.recordProbe(at.Add(3*time.Minute), "ultra", false, true)
	rows := m.probeHistoryTable().Rows
	if len(rows) != 3 || rows[0][3] != "Нет ответа" || rows[0][4] != "Нет ответа" ||
		rows[1][4] != "Ответила" || rows[2][4] != "Не проверялась" || rows[2][5] != "2" ||
		rows[2][0] != "21.11.2026 12:00:00" || rows[2][1] != "21.11.2026 12:01:00" {
		t.Fatalf("unexpected history: %v", rows)
	}
	m.recordProbe(at.Add(4*time.Minute), "other", false, true)
	if len(m.probeHistoryTable().Rows) != 4 {
		t.Fatal("protocol change was merged")
	}
	for i := 0; i < meduzaProbeHistoryLimit; i++ {
		m.recordProbe(at.Add(time.Duration(5+i)*time.Minute), "ultra", true, i%2 == 0)
	}
	rows = m.probeHistoryTable().Rows
	if len(rows) != meduzaProbeHistoryLimit || rows[len(rows)-1][0] != "21.11.2026 12:05:00" {
		t.Fatal("incorrect retention")
	}
}

func TestMeduzaProbeCheckpoint(t *testing.T) {
	oldDir := DataDir
	DataDir = t.TempDir()
	m := mod("meduza").(*meduza)
	oldHistory, oldStart := m.probeHistory, m.startProbeSeries
	t.Cleanup(func() { DataDir, m.probeHistory, m.startProbeSeries = oldDir, oldHistory, oldStart })
	m.restoreProbeHistory(nil)
	at := time.Now()
	m.recordProbe(at, "ultra", false, true)
	store := &historyStore{}
	if err := store.flush(at.Unix()); err != nil {
		t.Fatal(err)
	}
	m.restoreProbeHistory(nil)
	reloaded, _ := loadHistory(at.Unix())
	if reloaded.lastError != "" {
		t.Fatal(reloaded.lastError)
	}
	m.recordProbe(at.Add(time.Minute), "ultra", false, true)
	table := m.probeHistoryTable()
	if len(table.Rows) != 2 || len(table.ProblemRows) != 2 || table.Rows[1][5] != "1" {
		t.Fatal("lost checkpoint or merged across restart", table.Rows)
	}
}
