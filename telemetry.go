package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const historyStep = int64(5)
const historySeconds = int64(3600)
const historyBytes = 4 << 20
const historySeries = 128

type historySample struct {
	At     int64              `json:"at"`
	Values map[string]float64 `json:"values"`
}
type historyArchive struct {
	MeduzaProbes []meduzaProbeSeries `json:"meduzaProbes,omitempty"`
	Version      int                 `json:"version"`
	SavedAt      int64               `json:"savedAt"`
	Samples      []historySample     `json:"samples"`
	Decisions    []LogLine           `json:"decisions"`
}
type historyStore struct {
	mu        sync.Mutex
	writeMu   sync.Mutex
	samples   []historySample
	savedAt   int64
	lastError string
}

var telemetry *historyStore

func cleanHistoryValues(values map[string]float64) map[string]float64 {
	keys := make([]string, 0, len(values))
	for k, v := range values {
		if len(k) <= 128 && !math.IsNaN(v) && !math.IsInf(v, 0) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) > historySeries {
		keys = keys[:historySeries]
	}
	out := make(map[string]float64, len(keys))
	for _, k := range keys {
		out[k] = values[k]
	}
	return out
}

func (s *historyStore) add(at int64, values map[string]float64) {
	at = at / historyStep * historyStep
	values = cleanHistoryValues(values)
	s.mu.Lock()
	defer s.mu.Unlock()
	first := 0
	for first < len(s.samples) && s.samples[first].At <= at-historySeconds {
		first++
	}
	if first > 0 {
		s.samples = append([]historySample(nil), s.samples[first:]...)
	}
	if len(s.samples) > 0 {
		last := &s.samples[len(s.samples)-1]
		if at < last.At {
			return
		}
		if at == last.At {
			last.Values = values
			return
		}
	}
	s.samples = append(s.samples, historySample{at, values})
}

func loadHistory(now int64) (*historyStore, []LogLine) {
	s := &historyStore{}
	// Убираем только временные файлы собственного атомарного checkpoint после аварии.
	if entries, err := os.ReadDir(DataDir); err == nil {
		for _, entry := range entries {
			if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), ".telemetry.json.") && strings.HasSuffix(entry.Name(), ".tmp") {
				_ = os.Remove(filepath.Join(DataDir, entry.Name()))
			}
		}
	}
	f, err := os.Open(filepath.Join(DataDir, "telemetry.json"))
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		s.lastError = err.Error()
		return s, nil
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, historyBytes+1))
	var archive historyArchive
	if err == nil && len(data) > historyBytes {
		err = fmt.Errorf("история превышает 4 МиБ")
	}
	if err == nil {
		err = json.Unmarshal(data, &archive)
	}
	if err == nil && (archive.Version != 1 || len(archive.Samples) > int(historySeconds/historyStep)) {
		err = fmt.Errorf("неподдерживаемая история мониторинга")
	}
	if err != nil {
		s.lastError = err.Error()
		return s, nil
	}
	var previous int64
	for _, sample := range archive.Samples {
		if sample.At <= previous || sample.At%historyStep != 0 || sample.At > now+historyStep {
			s.lastError = "нарушен порядок времени истории"
			s.samples = nil
			return s, nil
		}
		previous = sample.At
		if sample.At > now-historySeconds {
			s.add(sample.At, sample.Values)
		}
	}
	if m, ok := mod("meduza").(*meduza); ok {
		m.restoreProbeHistory(archive.MeduzaProbes)
	}
	s.savedAt = archive.SavedAt
	return s, cleanHistoryDecisions(archive.Decisions)
}

func cleanHistoryDecisions(lines []LogLine) []LogLine {
	if len(lines) > 200 {
		lines = lines[len(lines)-200:]
	}
	out := append([]LogLine(nil), lines...)
	for i := range out {
		if len(out[i].Text) > 4096 {
			out[i].Text = string([]rune(out[i].Text[:4096])) + "…"
		}
		if len(out[i].T) > 64 {
			out[i].T = out[i].T[:64]
		}
		if len(out[i].Lvl) > 16 {
			out[i].Lvl = out[i].Lvl[:16]
		}
	}
	return out
}

func (s *historyStore) flush(now int64) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	archive := historyArchive{Version: 1, SavedAt: now, Samples: append([]historySample(nil), s.samples...)}
	s.mu.Unlock()
	if m, ok := mod("meduza").(*meduza); ok {
		m.mu.Lock()
		archive.MeduzaProbes = append([]meduzaProbeSeries(nil), m.probeHistory...)
		m.mu.Unlock()
	}
	archive.Decisions = cleanHistoryDecisions(snapshotLog(&decRing))
	first := 0
	for first < len(archive.Samples) && archive.Samples[first].At <= now-historySeconds {
		first++
	}
	archive.Samples = archive.Samples[first:]
	var data []byte
	var err error
	for {
		data, err = json.Marshal(archive)
		if err != nil || len(data) <= historyBytes {
			break
		}
		if len(archive.Samples) == 0 {
			err = fmt.Errorf("слишком большой журнал решений")
			break
		}
		archive.Samples = archive.Samples[max(1, len(archive.Samples)/4):]
	}
	if err == nil {
		err = saveFile("telemetry.json", data)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.lastError = err.Error()
		return err
	}
	s.savedAt, s.lastError = now, ""
	cutoff := now - historySeconds + historyStep
	if len(archive.Samples) > 0 {
		cutoff = archive.Samples[0].At
	}
	first = 0
	for first < len(s.samples) && s.samples[first].At < cutoff {
		first++
	}
	if first > 0 {
		s.samples = append([]historySample(nil), s.samples[first:]...)
	}
	return nil
}

func (s *historyStore) view(now int64) map[string]any {
	times := []int64{}
	series := map[string][]*float64{}
	s.mu.Lock()
	samples := append([]historySample(nil), s.samples...)
	saved, message := s.savedAt, s.lastError
	s.mu.Unlock()
	end := now / historyStep * historyStep
	begin := end - historySeconds + historyStep
	if len(samples) > 0 && samples[0].At > begin {
		begin = samples[0].At
	}
	if len(samples) > 0 {
		for at := begin; at <= end; at += historyStep {
			times = append(times, at)
		}
	}
	// Ограничение действует и на объединение рядов при смене клиентов/модулей.
	allowed := map[string]bool{}
	for i := len(samples) - 1; i >= 0 && len(allowed) < historySeries; i-- {
		if samples[i].At < begin || samples[i].At > end {
			continue
		}
		keys := make([]string, 0, len(samples[i].Values))
		for key := range samples[i].Values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if len(allowed) < historySeries {
				allowed[key] = true
			}
		}
	}
	for _, sample := range samples {
		if sample.At < begin || sample.At > end {
			continue
		}
		i := int((sample.At - begin) / historyStep)
		for key, value := range sample.Values {
			if !allowed[key] {
				continue
			}
			if series[key] == nil {
				series[key] = make([]*float64, len(times))
			}
			v := value
			series[key][i] = &v
		}
	}
	return map[string]any{"t": times, "series": series, "storage": map[string]any{"savedAt": saved, "error": message, "maxBytes": historyBytes, "retentionSeconds": historySeconds, "checkpointSeconds": 30}}
}

func initTelemetry() {
	var decisions []LogLine
	telemetry, decisions = loadHistory(time.Now().Unix())
	logMu.Lock()
	decRing = cleanHistoryDecisions(append(decisions, decRing...))
	logMu.Unlock()
	if telemetry.lastError != "" {
		Log("WARN", "История мониторинга: %s; сбор продолжится в памяти", telemetry.lastError)
	}
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-shutdown
		done := make(chan struct{})
		go func() { _ = telemetry.flush(time.Now().Unix()); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		os.Exit(0)
	}()
}

func collectHistory() {
	values := map[string]float64{}
	for _, m := range Mods {
		values[m.ID()+".level"] = float64(m.Status().Level)
		for k, v := range m.Metrics() {
			values[m.ID()+"."+k] = v
		}
	}
	for _, c := range wgMod.Clients() {
		values["client."+c.IP] = c.Tx
	}
	networkHistoryValues(values, time.Now().Unix())
	telemetry.add(time.Now().Unix(), values)
}
