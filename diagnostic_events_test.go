package main

import (
	"sync"
	"testing"
)

func TestDiagnosticEventCursor(t *testing.T) {
	l := diagnosticEventLog{epoch: "one"}
	initial := l.page("")
	if !initial.Reset {
		t.Fatal("initial snapshot required")
	}
	l.record("test.private", "private")
	for i := 0; i < diagnosticEventCapacity; i++ {
		l.record("routes.changed", "private-client-id")
	}
	full := l.page(initial.Cursor)
	if full.Reset || len(full.Events) != diagnosticEventCapacity {
		t.Fatal("oldest retained cursor rejected")
	}
	for i, e := range full.Events {
		if e.Sequence != uint64(i+1) || e.Module != "" || e.Type != "routes.changed" {
			t.Fatal("bad event", e)
		}
	}
	l.record("inet.lost", "private")
	next := l.page(full.Cursor)
	if next.Reset || len(next.Events) != 1 || next.Events[0].Module != "inet" {
		t.Fatal("missing increment")
	}
	if idle := l.page(next.Cursor); idle.Reset || len(idle.Events) != 0 {
		t.Fatal("idle cursor")
	}
	for _, bad := range []string{initial.Cursor, "other.127", "one.9999", "one.invalid"} {
		if !l.page(bad).Reset {
			t.Fatal("stale cursor accepted", bad)
		}
	}
}

func TestDiagnosticEventIndependentReaders(t *testing.T) {
	l := diagnosticEventLog{epoch: "test"}
	start := l.page("").Cursor
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 16; j++ {
				l.record("exit.changed", "meduza")
				l.page(start)
			}
		}()
	}
	wg.Wait()
	for i := 0; i < 2; i++ {
		p := l.page(start)
		if p.Reset || len(p.Events) != 64 {
			t.Fatal("reader consumed another reader's events")
		}
		for j, e := range p.Events {
			if e.Sequence != uint64(j+1) {
				t.Fatal("out of order")
			}
		}
	}
}
