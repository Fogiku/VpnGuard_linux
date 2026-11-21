package main

import (
	"slices"
	"time"
)

// Each entry is one completed invocation of ping, including failed invocations.
// Only the three built-in path IDs are eligible for the shared diagnostics.
type qualityWindow map[string][]qualityResult

var diagnosticQualityPaths = [...]string{"direct", "meduza", "awg"}

func (w qualityWindow) record(results []qualityResult) {
	for _, r := range results {
		if !slices.Contains(diagnosticQualityPaths[:], r.ID) {
			continue
		}
		rounds := w[r.ID]
		// A different target or interface starts a separate measurement series.
		if n := len(rounds); n > 0 {
			last := rounds[n-1]
			if last.Target != r.Target || last.Iface != r.Iface || r.At < last.At {
				rounds = nil
			}
		}
		for len(rounds) > 0 && (len(rounds) >= 16 || rounds[0].At <= r.At-diagnosticWindowSeconds) {
			rounds = rounds[1:]
		}
		w[r.ID] = append(rounds, r)
	}
}

type qualityPathSummary struct {
	ID         string   `json:"id"`
	LastAt     int64    `json:"lastAt"`
	Rounds     int      `json:"rounds"`
	Incomplete int      `json:"incomplete"`
	Sent       int      `json:"sent"`
	Received   int      `json:"received"`
	Loss       *float64 `json:"lossPct"`
	MaxMeanRTT *float64 `json:"maxMeanRttMs"`
	MaxJitter  *float64 `json:"maxJitterMs"`
}
type qualityWindowPage struct {
	SchemaVersion int                  `json:"schemaVersion"`
	From          int64                `json:"from"`
	Through       int64                `json:"through"`
	Paths         []qualityPathSummary `json:"paths"`
}

func (w qualityWindow) page(now int64) qualityWindowPage {
	p := qualityWindowPage{1, now - diagnosticWindowSeconds + 1, now, []qualityPathSummary{}}
	for _, id := range diagnosticQualityPaths {
		row := qualityPathSummary{ID: id}
		for _, r := range w[id] {
			if r.At < p.From || r.At > now {
				continue
			}
			row.LastAt = r.At
			row.Rounds++
			if r.Loss == nil {
				row.Incomplete++
				continue
			}
			row.Sent += r.Sent
			row.Received += r.Received
			if r.RTT != nil && (row.MaxMeanRTT == nil || *r.RTT > *row.MaxMeanRTT) {
				row.MaxMeanRTT = r.RTT
			}
			if r.Jitter != nil && (row.MaxJitter == nil || *r.Jitter > *row.MaxJitter) {
				row.MaxJitter = r.Jitter
			}
		}
		if row.Rounds == 0 {
			continue
		}
		if row.Sent > 0 {
			loss := 100 * float64(row.Sent-row.Received) / float64(row.Sent)
			row.Loss = &loss
		}
		p.Paths = append(p.Paths, row)
	}
	return p
}

func diagnosticQualityWindow() qualityWindowPage {
	networkTelemetry.Lock()
	defer networkTelemetry.Unlock()
	return networkTelemetry.window.page(time.Now().Unix())
}
