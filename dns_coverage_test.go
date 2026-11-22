package main

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDNSCoverageAddressExpressions(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.3")
	for _, tc := range []struct {
		expr         string
		found, valid bool
	}{
		{`"192.0.2.3"`, true, true}, {`"192.0.2.4"`, false, true},
		{`{"range":["192.0.2.1","192.0.2.3"]}`, true, true},
		{`{"prefix":{"addr":"192.0.2.0","len":30}}`, true, true},
		{`{"range":["192.0.2.3","192.0.2.1"]}`, false, false},
		{`{"prefix":{"addr":"192.0.2.1","len":33}}`, false, false}, {`null`, false, false},
	} {
		found, err := addressMember([]byte(tc.expr), ip)
		if found != tc.found || (err == nil) != tc.valid {
			t.Fatalf("%s: %v %v", tc.expr, found, err)
		}
	}
	if _, err := ruleSetContains(`{"nftables":[]}`, "missing", ip); err == nil {
		t.Fatal("missing set treated as empty")
	}
}

func TestDNSCoverageCacheSources(t *testing.T) {
	now := time.Unix(9999, 0)
	lookups := 0
	e := newDNSEngine(func(q []byte) ([]byte, error) {
		lookups++
		return dnsTestResponse(q, dnsTestA("cdn.test", "192.0.2.3", 4)), nil
	})
	old := routingDNS
	routingDNS = e
	defer func() { routingDNS = old }()
	e.now = func() time.Time { return now }
	e.lookup("cdn.test")
	if e.entries["cdn.test"].Source != "Обновление шлюзом" {
		t.Fatal("wrong refresh origin")
	}
	q, _ := dnsRequest("cdn.test")
	e.serve(q, nil)
	if e.entries["cdn.test"].Source != "Запрос через DNS-прокси" {
		t.Fatal("wrong proxy origin")
	}
	before := lookups
	if !strings.Contains(dnsCacheCoverage("cdn.test", "192.0.2.3"), "4 с") {
		t.Fatal("missing active TTL")
	}
	now = now.Add(4 * time.Second)
	if !strings.Contains(dnsCacheCoverage("cdn.test", "192.0.2.3"), "адреса нет") || lookups != before {
		t.Fatal("lookup resurrected expired record")
	}
}

func TestDNSCoverageIsolatedKernel(t *testing.T) {
	if os.Getenv("VPNGUARD_NETNS_TEST") != "1" {
		t.Skip("requires isolated Linux netns")
	}
	oldS, oldSim, oldRoutes := S, Sim, rt
	S, Sim = realSys{}, false
	defer func() { S, Sim, rt = oldS, oldSim, oldRoutes }()
	rt = Routes{Profiles: []Profile{{ID: "p1", Name: "Control", Rules: []Rule{{ID: "cdn", Title: "CDN", Match: "cdn.test"}}}}}
	name := routeAddressSet("p1_cdn")
	script := fmt.Sprintf("table inet vpnguard {\n set %s { type ipv4_addr; flags interval; elements = { 192.0.2.0/30, 192.0.2.20-192.0.2.25, 192.0.2.50 }; }\n}\n", name)
	if out, code := S.Run(3*time.Second, script, "nft", "-f", "-"); code != 0 {
		t.Fatal(out)
	}
	for _, ip := range []string{"192.0.2.1", "192.0.2.25", "192.0.2.50", "192.0.2.99"} {
		reply, err := dnsMod.Do("compare-address", map[string]string{"name": "cdn.test", "ip": ip, "rule": "p1_cdn"})
		want := "входит в действующий набор"
		if ip == "192.0.2.99" {
			want = "отсутствует в действующем наборе"
		}
		if err != nil || !strings.Contains(reply, want) {
			t.Fatal(ip, reply, err)
		}
	}
}
