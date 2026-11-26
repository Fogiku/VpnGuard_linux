package main

import (
	"testing"
	"time"
)

func TestDPIBindingRejectsReusedAndAmbiguousLifetime(t *testing.T) {
	c := dpiTestCapture()
	c.End = c.Start.Add(2 * time.Second)
	rows, err := parseNDPI42CSV(dpiCSVHeader+dpiCSVRow, c)
	if err != nil {
		t.Fatal(err)
	}
	d := rows[0]
	id := uint32(42)
	r := flowLifetime{Generation: "epoch:1", ObservedNewAt: 1699999999, Row: d.Flow}
	r.Row.ConntrackID = &id
	a := dpiBoundary{Frame: flowEventFrame{Epoch: "epoch", Rows: []flowLifetime{r}}, At: c.Start.Add(-time.Second)}
	b := dpiBoundary{Frame: flowEventFrame{Epoch: "epoch", Rows: []flowLifetime{r}}, At: c.End.Add(time.Second)}
	if _, err := bindDPIObservation(d, c, a, b); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*dpiBoundary){
		func(b *dpiBoundary) { b.Frame.Epoch = "restart" },
		func(b *dpiBoundary) { b.Frame.Rows[0].Generation = "epoch:2" },
		func(b *dpiBoundary) { b.Frame.Rows = nil },
		func(b *dpiBoundary) { b.Frame.Rows = append(b.Frame.Rows, r) },
		func(b *dpiBoundary) { b.At = c.Start },
		func(b *dpiBoundary) { b.Frame.Rows[0].Row.Zone = 5 },
	} {
		bad := b
		bad.Frame.Rows = append([]flowLifetime(nil), b.Frame.Rows...)
		change(&bad)
		if _, err := bindDPIObservation(d, c, a, bad); err == nil {
			t.Fatal("unrelated/ambiguous lifetime accepted")
		}
	}
}

func TestDisplayedDPILabelExpiresWithGeneration(t *testing.T) {
	now := time.Now()
	id := uint32(99)
	r := flowRow{Protocol: "udp", Source: "10.0.0.1", Destination: "10.0.0.2", SourcePort: 12123, DestinationPort: 53, ConntrackID: &id}
	d := dpiObservation{Flow: r, Source: wgMod.iface()}
	d.Flow.Application = "DNS"
	life := flowLifetime{Generation: "epoch:1", Row: r}
	s := &flowEventSession{last: now, frame: flowEventFrame{Epoch: "epoch", DrainedAtNs: now.UnixNano(), Rows: []flowLifetime{life}}}
	m := &flowModule{at: now.Add(-time.Millisecond), rows: []flowRow{r}, events: s, bindings: map[string]dpiBinding{life.Generation: {Epoch: "epoch", Generation: life.Generation, Observation: d}}}
	label := func(want string) {
		t.Helper()
		if got := m.Tables()[0].Rows[0][5]; got != want {
			t.Fatalf("want %s got %s", want, got)
		}
	}
	label("DNS")
	d.Flow.Application = "Unknown"
	m.bindings[life.Generation] = dpiBinding{Epoch: "epoch", Generation: life.Generation, Observation: d}
	label("Unknown")
	s.frame.Rows[0].Generation = "epoch:2"
	label("Нет привязки")
	s.frame.Rows[0] = life
	s.frame.DrainedAtNs = m.at.Add(-time.Millisecond).UnixNano()
	label("Нет привязки")
	s.frame.DrainedAtNs = now.UnixNano()
	m.truncated = true
	label("Нет привязки")
	m.truncated = false
	extra := r
	extra.Zone = 3
	m.rows = append(m.rows, extra)
	label("Нет привязки")
	m.rows = m.rows[:1]
	s.failed = true
	label("Нет привязки")
}
