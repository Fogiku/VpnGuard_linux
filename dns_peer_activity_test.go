package main

import (
	"strings"
	"testing"
	"time"
)

func TestDNSPeerAnswerRotation(t *testing.T) {
	e := newDNSEngine(nil)
	now := time.Unix(100, 0)
	e.now = func() time.Time { return now }
	name := "example.test"
	client := "192.0.2.8"
	e.tracked[name] = now
	q, err := dnsRequest(name)
	if err != nil {
		t.Fatal(err)
	}
	send := func(ip string) { e.sentDNS("WG", client, false, dnsTestResponse(q, dnsTestA(name, ip, 30))) }
	covers := func(ip string) string { return e.peerCoverage(client, name, ip) }
	send("203.0.113.1")
	send("203.0.113.2")
	if !strings.Contains(covers("203.0.113.2"), "остаток TTL 30") || !strings.Contains(covers("203.0.113.1"), "не подтверждено") {
		t.Fatal("did not use most recent answer")
	}
	truncated := dnsTestResponse(q)
	truncated[2] |= 2
	e.sentDNS("WG", client, true, truncated)
	failed := dnsTestResponse(q)
	failed[3] = (failed[3] & 0xf0) | 2
	e.sentDNS("WG", client, false, failed)
	now = now.Add(30 * time.Second)
	if !strings.Contains(covers("203.0.113.2"), "TTL истёк") {
		t.Fatal("lost expired evidence")
	}
	if !strings.Contains(e.peerCoverage("192.0.2.9", name, "203.0.113.2"), "нет сохранённого") {
		t.Fatal("mixed clients")
	}
	row := e.peerTable().Rows[0]
	if strings.Join(row[2:7], ",") != "3,1,0,1,1" {
		t.Fatal(row)
	}
}
