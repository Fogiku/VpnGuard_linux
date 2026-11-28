package main

import (
	"testing"
	"time"
)

func TestLANSelectionRotatesWithoutSelectingWG(t *testing.T) {
	setup(t)
	m := flowModule{at: time.Now()}
	for _, ip := range []string{"10.253.0.2", "192.168.1.4", "192.168.1.5", "203.0.113.2"} {
		m.rows = append(m.rows, flowRow{Source: ip, Mark: 19 << 16})
	}
	for _, want := range []string{"", "192.168.1.4", "", "192.168.1.5", "", "192.168.1.4"} {
		result := m.nextLAN()
		got := ""
		if len(result) > 0 {
			got = result[0]
		}
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

func TestUDP443Pending(t *testing.T) {
	id := uint32(2)
	no := false
	r := flowRow{Protocol: "udp", DestinationPort: 443, Mark: 19 << 16, ConntrackID: &id, SeenReply: &no}
	rows := []flowRow{r}
	if len(repeatedUnanswered(rows, rows, true)) != 1 {
		t.Fatal("missed UDP/443")
	}
	rows[0].DestinationPort = 53
	if len(repeatedUnanswered(rows, rows, true)) != 0 {
		t.Fatal("included unrelated UDP")
	}
}
