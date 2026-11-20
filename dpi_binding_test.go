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
