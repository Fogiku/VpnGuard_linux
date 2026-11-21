package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestQualityWindowRounds(t *testing.T) {
	w := qualityWindow{}
	zero, loss, rtt, jitter := 0., 100., 18., 2.
	for _, r := range []qualityResult{
		{ID: "direct", At: 100, Loss: &loss, Sent: 5},
		{ID: "direct", At: 101, Loss: &zero, Sent: 5, Received: 5, RTT: &rtt, Jitter: &jitter},
		{ID: "direct", At: 150, Loss: &loss, Sent: 5},
		{ID: "direct", At: 180, Sent: 2},
		{ID: "meduza", At: 175},
		{ID: "awg", At: 401},
		{ID: "private-id", At: 185},
	} {
		r.Target = "private-target"
		r.Iface = "private-iface"
		w.record([]qualityResult{r})
	}
	p := w.page(400)
	if p.From != 101 || p.Through != 400 || len(p.Paths) != 2 {
		t.Fatal(p)
	}
	d := p.Paths[0]
	if d.ID != "direct" || d.LastAt != 180 || d.Rounds != 3 || d.Incomplete != 1 || d.Sent != 10 || d.Received != 5 || *d.Loss != 50 || *d.MaxMeanRTT != 18 || *d.MaxJitter != 2 {
		t.Fatal(d)
	}
	m := p.Paths[1]
	if m.Loss != nil || m.MaxMeanRTT != nil || m.MaxJitter != nil || m.Incomplete != 1 {
		t.Fatal(m)
	}
	data, _ := json.Marshal(p)
	if strings.Contains(string(data), "private") {
		t.Fatal(string(data))
	}
	w.record([]qualityResult{{ID: "direct", At: 402, Target: "changed"}})
	if got := w.page(402).Paths[0]; got.Rounds != 1 || got.Loss != nil {
		t.Fatal(got)
	}
	for i := 0; i < 20; i++ {
		w.record([]qualityResult{{ID: "direct", At: int64(403 + i), Target: "changed"}})
	}
	if n := len(w["direct"]); n != 16 {
		t.Fatal(n)
	}
	if got := w.page(1000).Paths; got == nil || len(got) != 0 {
		t.Fatal(got)
	}
}
