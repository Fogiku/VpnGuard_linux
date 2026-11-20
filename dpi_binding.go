package main

import (
	"fmt"
	"time"
)

// Immutable copy for a bounded capture. Never use a snapshot as lifetime proof.
type dpiBoundary struct {
	Frame flowEventFrame
	At    time.Time
}

func (s *flowEventSession) dpiBoundary() (dpiBoundary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || s.frame.Epoch == "" || time.Since(s.last) > 4*time.Second {
		return dpiBoundary{}, fmt.Errorf("event continuity unavailable")
	}
	f := s.frame
	f.Rows = append([]flowLifetime(nil), s.frame.Rows...)
	return dpiBoundary{Frame: f, At: s.last}, nil
}

type dpiBinding struct {
	Epoch, Generation string
	Observation       dpiObservation
}

// Candidate binding only: event delivery can lag. Caller must also obtain a
// drained event barrier after capture before publishing any live classification.
func bindDPIObservation(d dpiObservation, c dpiCapture, before, after dpiBoundary) (dpiBinding, error) {
	fail := func() (dpiBinding, error) { return dpiBinding{}, fmt.Errorf("DPI lifetime cannot be established") }
	if before.Frame.Epoch == "" || before.Frame.Epoch != after.Frame.Epoch || before.At.After(c.Start) || after.At.Before(c.End) || c.End.Before(c.Start) || c.End.Sub(c.Start) > 3*time.Second || c.Start.Sub(before.At) > 4*time.Second || after.At.Sub(c.End) > 4*time.Second || d.Source != c.Source || !c.GuessDisabled || c.Version != "4.2.0" || d.First.Before(c.Start) || d.Last.After(c.End) || d.Last.Before(d.First) {
		return fail()
	}
	find := func(b dpiBoundary) (flowLifetime, bool) {
		var found flowLifetime
		count := 0
		for _, r := range b.Frame.Rows {
			if d.matches(r.Row, c.Start, c.End) {
				found = r
				count++
			}
		}
		return found, count == 1
	}
	a, ok := find(before)
	if !ok {
		return fail()
	}
	b, ok := find(after)
	if !ok {
		return fail()
	}
	if a.Generation == "" || a.Generation != b.Generation || a.Row.ConntrackID == nil || b.Row.ConntrackID == nil || *a.Row.ConntrackID != *b.Row.ConntrackID || a.Row.Zone != b.Row.Zone || a.ObservedNewAt != b.ObservedNewAt || a.ObservedNewAt > float64(c.Start.UnixNano())/1e9 {
		return fail()
	}
	return dpiBinding{Epoch: before.Frame.Epoch, Generation: a.Generation, Observation: d}, nil
}
