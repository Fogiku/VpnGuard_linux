package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestQualityPingPartialLossAndJitter(t *testing.T) {
	output := `64 bytes: icmp_seq=1 ttl=64 time=10.0 ms
64 bytes: icmp_seq=2 ttl=64 time=14.0 ms
64 bytes: icmp_seq=2 ttl=64 time=99.0 ms (DUP!)
64 bytes: icmp_seq=4 ttl=64 time=30.0 ms
64 bytes: icmp_seq=5 ttl=64 time=36.0 ms
5 packets transmitted, 4 received, 20% packet loss
rtt min/avg/max/mdev = 10.000/22.500/36.000/9.000 ms`
	r := parseQualityPing(output, 1, 5)
	if r.Loss == nil || *r.Loss != 20 || r.RTT == nil || *r.RTT != 22.5 || r.Jitter == nil || *r.Jitter != 5 || r.JitterPairs != 2 {
		t.Fatalf("incorrect loss/RTT/jitter: %+v", r)
	}
	// Потерянный пакет 3 не создаёт искусственную пару RTT между 2 и 4.
	for _, tc := range []struct {
		output string
		code   int
		loss   bool
	}{
		{"5 packets transmitted, 0 received, 100% packet loss", 1, true},
		{"ping: Operation not permitted", 2, false},
		{"3 packets transmitted, 0 received, 100% packet loss", 1, false},
		{"5 packets transmitted, 9 received", 0, false},
		{"5 packets transmitted, 5 received", -1, false},
	} {
		r = parseQualityPing(tc.output, tc.code, 5)
		if (r.Loss != nil) != tc.loss || r.RTT != nil || r.Jitter != nil || r.Error == "" {
			t.Fatalf("unknown measurements converted to values: %+v", r)
		}
	}
	for _, ip := range []string{"", "example.com", "0.0.0.0", "255.255.255.255", "224.1.1.1", "::ffff:1.1.1.1", "1.1.1.1;reboot"} {
		if validQualityIP(ip) {
			t.Fatal("invalid target accepted", ip)
		}
	}
}

func TestRuleCountersAggregatePortsAndPreserveUnknown(t *testing.T) {
	entry := func(table, chain, tag string, p, b uint64) string {
		return fmt.Sprintf(`{"rule":{"family":"inet","table":%q,"chain":%q,"comment":%q,"expr":[{"counter":{"packets":%d,"bytes":%d}}]}}`, table, chain, tag, p, b)
	}
	doc := `{"nftables":[` + strings.Join([]string{entry("vpnguard", "classify", "p1_r1", 2, 120), entry("vpnguard", "classify", "p1_r1", 3, 240), entry("other", "classify", "p1_r1", 999, 999), entry("vpnguard", "other", "p1_r1", 999, 999), entry("vpnguard", "classify", "foreign", 999, 999)}, ",") + `]}`
	rows, truncated, err := parseRuleCounts(doc, map[string]string{"p1_r1": "Rule", "p1_r2": "Uncompiled rule"}, &zapretTraffic{})
	if err != nil || truncated || len(rows) != 2 || *rows[0].Packets != 5 || *rows[0].Bytes != 360 || rows[1].Packets != nil {
		t.Fatal("counter ownership or aggregation failed", rows, err)
	}
	for _, bad := range []string{`{`, `{"nftables":[` + entry("vpnguard", "classify", "p1_r1", ^uint64(0), 1) + `,` + entry("vpnguard", "classify", "p1_r1", 1, 1) + `]}`} {
		if _, _, err := parseRuleCounts(bad, map[string]string{"p1_r1": "Rule"}, &zapretTraffic{}); err == nil {
			t.Fatal("invalid counter accepted")
		}
	}
}

type observingSys struct {
	Sys
	commands []string
}

func (s *observingSys) Run(d time.Duration, in, name string, args ...string) (string, int) {
	s.commands = append(s.commands, name+" "+strings.Join(args, " "))
	return s.Sys.Run(d, in, name, args...)
}

func TestNetworkTelemetryOnlyObservesAndExpires(t *testing.T) {
	setup(t)
	oldS := S
	defer func() { S = oldS }()
	s := &observingSys{Sys: S}
	S = s
	oldWindow := networkTelemetry.window
	networkTelemetry.window = nil
	defer func() { networkTelemetry.window = oldWindow }()
	oldQuality, oldCounts := networkTelemetry.Quality, networkTelemetry.Counters
	defer func() { networkTelemetry.Quality, networkTelemetry.Counters = oldQuality, oldCounts }()
	oldApplied := applyInfo
	defer func() { applyInfo = oldApplied }()
	applyInfo = "test generation"
	collectQuality()
	collectRuleCounts()
	if len(networkTelemetry.Quality) == 0 || networkTelemetry.Quality[0].Loss == nil || networkTelemetry.Counters.Error != "" {
		t.Fatal("observer produced no measurements", networkTelemetry.Quality, networkTelemetry.Counters)
	}
	for _, cmd := range s.commands {
		if !strings.HasPrefix(cmd, "env LC_ALL=C ping ") && cmd != "nft -j list table inet vpnguard" {
			t.Fatal("observer changed the system", cmd)
		}
	}
	values := map[string]float64{}
	networkHistoryValues(values, time.Now().Unix())
	if _, ok := values["quality.direct.rtt_ms"]; !ok {
		t.Fatal("quality missing from history")
	}
	values = map[string]float64{}
	networkHistoryValues(values, time.Now().Unix()+60)
	if len(values) != 0 {
		t.Fatal("stale observations persisted as current", values)
	}
	if err := setCfg("net.qualityEnabled", "false"); err != nil {
		t.Fatal(err)
	}
	commands := len(s.commands)
	collectQuality()
	if len(s.commands) != commands || len(networkTelemetry.Quality) != 0 || len(networkTelemetry.window) != 0 {
		t.Fatal("disabled observer still probes")
	}
}

func TestQualityLoopbackIsolatedKernel(t *testing.T) {
	if os.Getenv("VPNGUARD_NETNS_TEST") != "1" {
		t.Skip("requires isolated Linux namespace")
	}
	oldS := S
	defer func() { S = oldS }()
	S = realSys{}
	kernelCommand(t, "ip", "link", "set", "lo", "up")
	output, code := S.Run(6*time.Second, "", "env", "LC_ALL=C", "ping", "-4", "-n", "-c", "5", "-i", "0.2", "-W", "1", "-w", "4", "-I", "lo", "127.0.0.1")
	r := parseQualityPing(output, code, 5)
	if r.Loss == nil || *r.Loss != 0 || r.RTT == nil || r.Jitter == nil || r.JitterPairs != 4 {
		t.Fatalf("real ICMP parser: %+v\n%s", r, output)
	}
}

func TestRuleCountersIsolatedKernel(t *testing.T) {
	if os.Getenv("VPNGUARD_NETNS_TEST") != "1" {
		t.Skip("requires isolated Linux namespace")
	}
	oldS := S
	defer func() { S = oldS }()
	S = realSys{}
	kernelCommand(t, "ip", "link", "set", "lo", "up")
	script := `table inet vpnguard {
 chain classify {
  type filter hook output priority filter; policy accept;
  ip daddr 127.0.0.1 counter comment "p1_r1"
 }
}`
	if out, code := S.Run(time.Second, script, "nft", "-f", "-"); code != 0 {
		t.Fatal(out)
	}
	kernelCommand(t, "ping", "-n", "-q", "-c", "5", "-i", "0.2", "-W", "1", "127.0.0.1")
	var previous uint64
	for i := 0; i < 2; i++ {
		out, code := run("nft", "-j", "list", "table", "inet", "vpnguard")
		if code != 0 {
			t.Fatal(out)
		}
		rows, _, err := parseRuleCounts(out, map[string]string{"p1_r1": "Loopback"}, &zapretTraffic{})
		if err != nil || len(rows) != 1 || rows[0].Packets == nil || *rows[0].Packets < 10 || rows[0].Bytes == nil || *rows[0].Bytes == 0 {
			t.Fatal("real counters missing", rows, err, out)
		}
		if i > 0 && *rows[0].Packets != previous {
			t.Fatal("reading reset a counter")
		}
		previous = *rows[0].Packets
	}
}

func TestZapretRates(t *testing.T) {
	sample := func(at int64, bytes uint64) ruleCountView {
		return ruleCountView{At: at, Revision: 1, Zapret: zapretTraffic{Out: &packetTotals{Bytes: bytes}}}
	}
	old := sample(100, 1000)
	for _, tc := range []struct {
		at    int64
		bytes uint64
		want  float64
	}{
		{110, 2000, 800}, {110, 1000, 0}, {121, 3000, -1}, {110, 20, -1},
	} {
		got := zapretOutRate(old, sample(tc.at, tc.bytes))
		if tc.want < 0 && got != nil || tc.want >= 0 && (got == nil || *got != tc.want) {
			t.Fatalf("unexpected speed %+v: %v", tc, got)
		}
	}
	next := sample(110, 2000)
	next.Revision++
	if zapretOutRate(old, next) != nil || zapretOutRate(ruleCountView{}, next) != nil {
		t.Fatal("invalid baseline")
	}
}

func TestZapretCountersKernel(t *testing.T) {
	if os.Getenv("VPNGUARD_NETNS_TEST") != "1" {
		t.Skip("requires isolated Linux network namespace")
	}
	old := S
	S = realSys{}
	defer func() { S = old }()
	kernelCommand(t, "ip", "link", "set", "lo", "up")
	// Mark only the fixture sender. Count all selected packets; queue a subset.
	script := "table inet vpnguard {\n chain output { type route hook output priority mangle; policy accept; ip saddr 127.0.0.2 meta mark set 0x13\n }\n" +
		zapretCounterChain(`meta mark 0x13 oifname "lo"`) + "}\n"
	if out, code := S.Run(4*time.Second, script, "nft", "-f", "-"); code != 0 {
		t.Fatal(out)
	}
	kernelCommand(t, "sysctl", "-w", "net.netfilter.nf_conntrack_acct=1")
	// Include marked traffic outside the queue's port filter and unmarked traffic to port 443.
	kernelCommand(t, "python3", "-c", `import socket
for port in (443,1443):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as listener:
        listener.bind(("127.0.0.1",port))
        listener.settimeout(2)
        for addr in ("127.0.0.2","127.0.0.3"):
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.bind((addr,0))
                for i in range(12):
                    client.sendto(b'x',listener.getsockname())
                    listener.recvfrom(64)`)
	data, code := run("nft", "-j", "list", "table", "inet", "vpnguard")
	var v zapretTraffic
	if _, _, err := parseRuleCounts(data, nil, &v); code != 0 || err != nil || v.Out == nil || v.UDP == nil || v.TCP == nil {
		t.Fatal(data, err)
	}
	if v.Out.Packets != 24 || v.Out.Bytes != 24*29 || v.UDP.Packets != 9 || v.TCP.Packets != 0 {
		t.Fatalf("unexpected counts out=%+v udp=%+v tcp=%+v", v.Out, v.UDP, v.TCP)
	}
}
