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
	if s == nil {
		return dpiBoundary{}, fmt.Errorf("events disabled")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Unix(0, s.frame.DrainedAtNs)
	if s.failed || s.frame.Epoch == "" || cutoff.After(s.last) || time.Since(cutoff) > 4*time.Second {
		return dpiBoundary{}, fmt.Errorf("event continuity unavailable")
	}
	f := s.frame
	f.Rows = append([]flowLifetime(nil), s.frame.Rows...)
	return dpiBoundary{Frame: f, At: cutoff}, nil
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

// Labels apply to the generation observed on both sides of the sample.
// Recheck the current frame after the snapshot, including zone and original tuple.
type dpiTuple struct {
	Protocol, Source, Destination string
	SourcePort, DestinationPort   int
}

func originalTuple(r flowRow) dpiTuple {
	return dpiTuple{r.Protocol, r.Source, r.Destination, r.SourcePort, r.DestinationPort}
}

type dpiRowKey struct {
	ID   uint32
	Zone uint16
	dpiTuple
}

func dpiKey(r flowRow) dpiRowKey {
	return dpiRowKey{*r.ConntrackID, r.Zone, originalTuple(r)}
}

func (m *flowModule) snapshotLabels() map[dpiRowKey]dpiObservation {
	if len(m.bindings) == 0 || m.at.IsZero() || m.truncated {
		return nil
	}
	current, err := m.events.dpiBoundary()
	if err != nil || current.At.Before(m.at) {
		return nil
	}
	// The DPI export has no zone. Suppress tuples duplicated in the full snapshot.
	counts := map[dpiTuple]int{}
	for _, r := range m.rows {
		counts[originalTuple(r)]++
	}
	labels := map[dpiRowKey]dpiObservation{}
	for _, life := range current.Frame.Rows {
		b, ok := m.bindings[life.Generation]
		if ok && b.Epoch == current.Frame.Epoch && life.Row.ConntrackID != nil && counts[originalTuple(life.Row)] == 1 && (b.Observation.Source == wgMod.iface() || m.sampleInterface != "" && b.Observation.Source == m.sampleInterface) {
			labels[dpiKey(life.Row)] = b.Observation
		}
	}
	return labels
}
