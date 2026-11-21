package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

//go:embed deploy/flow_events.py
var flowEventsScript string

type flowEventRunner interface {
	FlowEvents(context.Context, string, func(string) error) error
}
type flowLifetime struct {
	Generation    string  `json:"generation"`
	ObservedNewAt float64 `json:"observedNewAt"`
	Row           flowRow `json:"row"`
}
type lifecycleCounters struct {
	Opened            uint64 `json:"opened"`
	Completed         uint64 `json:"completed"`
	UnmatchedUpdates  uint64 `json:"unmatchedUpdates"`
	UnmatchedDestroys uint64 `json:"unmatchedDestroys"`
}
type lifecycleSummary struct {
	Epoch  string `json:"epoch"`
	At     int64  `json:"at"`
	Active int    `json:"active"`
	lifecycleCounters
}
type flowEventFrame struct {
	lifecycleCounters
	Epoch string         `json:"epoch"`
	Rows  []flowLifetime `json:"rows"`
}
type flowEventSession struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
	frame  flowEventFrame
	last   time.Time
	failed bool
}

func flowEventProgram() string {
	// Keep both embedded parsers in one stdin program; no installed Python files.
	snapshot := strings.Split(flowSnapshotScript, "if __name__ == '__main__':")[0]
	events := strings.Split(flowEventsScript, "if __name__ == '__main__':")[0]
	events = strings.ReplaceAll(events, "from flow_snapshot import flow", "")
	return snapshot + "\n" + events + "\nstream_events()\n"
}
func startFlowEvents(r flowEventRunner) *flowEventSession {
	ctx, cancel := context.WithCancel(context.Background())
	s := &flowEventSession{cancel: cancel, done: make(chan struct{}), last: time.Now()}
	go func() {
		defer close(s.done)
		defer cancel()
		defer func() { s.mu.Lock(); s.frame = flowEventFrame{}; s.failed = true; s.mu.Unlock() }()
		_ = r.FlowEvents(ctx, flowEventProgram(), func(line string) error {
			var f flowEventFrame
			if len(line) > 1<<20 || json.Unmarshal([]byte(line), &f) != nil || len(f.Epoch) != 32 || f.Rows == nil || len(f.Rows) > 512 {
				return fmt.Errorf("invalid event heartbeat")
			}
			seen := map[string]bool{}
			for _, row := range f.Rows {
				if row.Row.ConntrackID == nil || !strings.HasPrefix(row.Generation, f.Epoch+":") || row.ObservedNewAt <= 0 || seen[row.Generation] {
					return fmt.Errorf("invalid event lifetime")
				}
				seen[row.Generation] = true
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.frame = f
			s.last = time.Now()
			return nil
		})
	}()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.mu.Lock()
				stale := time.Since(s.last) > 4*time.Second
				if stale {
					s.frame = flowEventFrame{}
					s.failed = true
				}
				s.mu.Unlock()
				if stale {
					cancel()
					return
				}
			}
		}
	}()
	return s
}
func (s *flowEventSession) stop() {
	s.cancel()
	s.mu.Lock()
	s.frame = flowEventFrame{}
	s.failed = true
	s.mu.Unlock()
	<-s.done
	s.mu.Lock()
	s.frame = flowEventFrame{}
	s.mu.Unlock()
}
func (s *flowEventSession) summary() *lifecycleSummary {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || s.frame.Epoch == "" || time.Since(s.last) > 4*time.Second {
		return nil
	}
	return &lifecycleSummary{Epoch: s.frame.Epoch, At: s.last.Unix(), Active: len(s.frame.Rows), lifecycleCounters: s.frame.lifecycleCounters}
}
