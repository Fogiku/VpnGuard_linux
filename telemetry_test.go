package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHistoryRestartPreservesDataAndGaps(t *testing.T) {
	oldDir, oldRing := DataDir, snapshotLog(&decRing)
	defer func() { DataDir, decRing = oldDir, oldRing }()
	DataDir = t.TempDir()
	decRing = []LogLine{{"2026-11-17 00:00:00", "INFO", "decision"}}
	s := &historyStore{}
	s.add(10000, map[string]float64{"vpn.level": 0, "vpn.rx": 42, "removed": 7})
	s.add(10005, map[string]float64{"vpn.level": 2, "vpn.rx": 21})
	if err := s.flush(10006); err != nil {
		t.Fatal(err)
	}
	loaded, decisions := loadHistory(10020)
	if loaded.lastError != "" || len(decisions) != 1 || decisions[0].Text != "decision" {
		t.Fatal("checkpoint not restored", loaded.lastError, decisions)
	}
	loaded.add(10020, map[string]float64{"new.level": 0})
	view := loaded.view(10020)
	times, series := view["t"].([]int64), view["series"].(map[string][]*float64)
	if len(times) != 5 || *series["vpn.rx"][0] != 42 || series["vpn.rx"][2] != nil || series["removed"][1] != nil || series["new.level"][0] != nil || *series["new.level"][4] != 0 {
		t.Fatal("missing data was shifted or replaced by zero", view)
	}
}

func TestHistoryWriteFailureKeepsMemoryAndRecovers(t *testing.T) {
	oldDir := DataDir
	defer func() { DataDir = oldDir }()
	DataDir = t.TempDir()
	path := filepath.Join(DataDir, "telemetry.json")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	s := &historyStore{}
	s.add(10000, map[string]float64{"vpn.level": 0})
	if err := s.flush(10000); err == nil || s.lastError == "" || len(s.samples) != 1 {
		t.Fatal("storage error lost or memory dropped")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := s.flush(10005); err != nil || s.lastError != "" || s.savedAt != 10005 {
		t.Fatal("storage did not recover", err)
	}
}

func TestHistoryCorruptionAndRetentionLimits(t *testing.T) {
	oldDir := DataDir
	defer func() { DataDir = oldDir }()
	DataDir = t.TempDir()
	path := filepath.Join(DataDir, "telemetry.json")
	for _, contents := range []string{`{`, `{"version":99}`, strings.Repeat(" ", historyBytes+1)} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		s, _ := loadHistory(10000)
		if s.lastError == "" || len(s.samples) != 0 {
			t.Fatal("invalid archive accepted")
		}
	}
	s := &historyStore{}
	for i := int64(0); i <= 800; i++ {
		s.add(10000+i*5, map[string]float64{"vpn.rx": float64(i), "invalid": math.Inf(1)})
	}
	if len(s.samples) != 720 {
		t.Fatal("sample retention exceeded", len(s.samples))
	}
	if err := s.flush(14000); err != nil {
		t.Fatal(err)
	}
	loaded, _ := loadHistory(17605)
	if loaded.lastError != "" || len(loaded.samples) != 0 {
		t.Fatal("old samples retained", loaded.lastError)
	}
}

func TestHistoryByteLimitAndSeriesChurn(t *testing.T) {
	oldDir, oldRing := DataDir, snapshotLog(&decRing)
	defer func() { DataDir, decRing = oldDir, oldRing }()
	DataDir = t.TempDir()
	decRing = []LogLine{{T: "2026-11-17", Lvl: "INFO", Text: strings.Repeat("x", 20000)}}
	s := &historyStore{}
	for i := 0; i < 720; i++ {
		values := map[string]float64{}
		for j := 0; j < 140; j++ {
			values[fmt.Sprintf("metric.%s.%d.%d", strings.Repeat("a", 80), i, j)] = 123456789.123456
		}
		s.add(10000+int64(i)*5, values)
	}
	view := s.view(13595)
	if len(view["series"].(map[string][]*float64)) > historySeries {
		t.Fatal("series churn exceeded response budget")
	}
	if err := s.flush(13595); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(DataDir, "telemetry.json"))
	if err != nil || len(data) > historyBytes {
		t.Fatal("disk budget exceeded", err, len(data))
	}
	var archive historyArchive
	if err := json.Unmarshal(data, &archive); err != nil || len(archive.Samples) >= 720 || len(archive.Decisions[0].Text) > 4100 {
		t.Fatal("compaction failed", err)
	}
}
