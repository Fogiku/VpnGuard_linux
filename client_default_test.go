package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func clientDefaultFixture(t *testing.T) string {
	t.Helper()
	setup(t)
	cfgMap["wg.iface"] = "lo"
	wgMod.d.Clients = []*WgClient{{IP: "127.0.0.2"}, {IP: "127.0.0.3"}}
	rt = Routes{
		Profiles: []Profile{{ID: "p1", Name: "Profile", Rules: []Rule{
			{ID: "service", Match: "udp:30901-30902", Exit: "zapret"},
			{ID: "fallback", Last: true, Exit: "direct"},
		}}},
		Overrides: map[string][]Rule{"127.0.0.2": {
			{ID: "nozapret", Last: true, Exit: "meduza"},
			{ID: "exception", Match: "udp:30901", Exit: "direct"},
		}},
	}
	script, _ := Compile()
	return script
}

func TestClientDefaultFollowsProfileConditions(t *testing.T) {
	script := clientDefaultFixture(t)
	prev := -1
	for _, tag := range []string{"ov_127.0.0.2_exception", "p1_service", "ov_127.0.0.2_nozapret", "p1_fallback"} {
		i := strings.Index(script, `comment "`+tag+`"`)
		if i <= prev {
			t.Fatalf("rule %s missing or out of order:\n%s", tag, script)
		}
		prev = i
	}
}

func TestClientDefaultIsolatedKernel(t *testing.T) {
	if os.Getenv("VPNGUARD_NETNS_TEST") != "1" {
		t.Skip("requires isolated Linux network namespace")
	}
	script := clientDefaultFixture(t)
	sim := S
	S = realSys{}
	defer func() { S = sim }()
	kernelCommand(t, "ip", "link", "set", "lo", "up")
	if out, code := S.Run(5*time.Second, script, "nft", "-f", "-"); code != 0 {
		t.Fatal(out)
	}
	kernelCommand(t, "python3", "-c", `import socket
for port in (30901,30902,30903):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server:
        server.settimeout(2)
        server.bind(("127.0.0.1",port))
        for peer in ("127.0.0.2","127.0.0.3"):
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
                sender.bind((peer,0))
                sender.sendto(b'x',server.getsockname())
                server.recvfrom(64)`)
	out, code := run("nft", "-j", "list", "table", "inet", "vpnguard")
	want := map[string]uint64{"ov_127.0.0.2_exception": 1, "p1_service": 3, "ov_127.0.0.2_nozapret": 1, "p1_fallback": 1}
	labels := map[string]string{}
	for k := range want {
		labels[k] = k
	}
	rows, _, err := parseRuleCounts(out, labels, &zapretTraffic{})
	if err != nil || code != 0 {
		t.Fatal(err, out)
	}
	for _, r := range rows {
		if r.Packets == nil || *r.Packets != want[r.Tag] {
			t.Fatal("unexpected matches", r.Tag, out)
		}
	}
}
