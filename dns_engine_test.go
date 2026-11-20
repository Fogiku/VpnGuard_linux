package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
	"vpnguard/internal/dnsmessage"
)

func dnsTestA(name, ip string, ttl uint32) dnsmessage.Resource {
	n, _ := dnsmessage.NewName(name + ".")
	var a [4]byte
	copy(a[:], net.ParseIP(ip).To4())
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.AResource{A: a}}
}
func dnsTestResponse(packet []byte, answers ...dnsmessage.Resource) []byte {
	request, _ := dnsQuestion(packet, false)
	reply := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, RecursionAvailable: true}, Questions: request.Questions, Answers: answers}
	out, _ := reply.Pack()
	return out
}

func TestDNSTTLRotationAndFailure(t *testing.T) {
	now := time.Unix(10000, 0)
	ip := "203.0.113.1"
	fail := false
	e := newDNSEngine(func(q []byte) ([]byte, error) {
		if fail {
			return nil, fmt.Errorf("upstream unavailable")
		}
		return dnsTestResponse(q, dnsTestA("example.test", ip, 10)), nil
	})
	e.now = func() time.Time { return now }
	if got := e.lookup("example.test"); len(got) != 1 || got[0] != ip {
		t.Fatal(got)
	}
	now = now.Add(3 * time.Second)
	ip = "203.0.113.2"
	if err := e.query("example.test"); err != nil {
		t.Fatal(err)
	}
	if got := e.lookup("example.test"); len(got) != 2 {
		t.Fatal("old client answer lost before TTL", got)
	}
	now = now.Add(8 * time.Second)
	fail = true
	_ = e.query("example.test")
	if got := e.lookup("example.test"); len(got) != 1 || got[0] != ip {
		t.Fatal("TTL or last valid answer wrong", got)
	}
	now = now.Add(3 * time.Second)
	if got := e.lookup("example.test"); len(got) != 0 {
		t.Fatal("expired answer reused during failure", got)
	}
}

func TestDNSIgnoresOldSettingsResponse(t *testing.T) {
	var e *dnsEngine
	e = newDNSEngine(func(q []byte) ([]byte, error) {
		e.mu.Lock()
		e.generation++
		e.mu.Unlock()
		return dnsTestResponse(q, dnsTestA("example.test", "203.0.113.1", 60)), nil
	})
	if got := e.lookup("example.test"); len(got) != 0 {
		t.Fatal("response from old settings cached", got)
	}
	q, _ := dnsRequest("example.test")
	reply, err := dnsQuestion(e.serve(q, nil), true)
	if err != nil || reply.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("response from old settings forwarded", reply, err)
	}
}

func TestDNSExistingResolverReadOnly(t *testing.T) {
	if os.Getenv("VPNGUARD_DNS_LIVE_TEST") != "1" {
		t.Skip("requires existing systemd-resolved; read-only DNS test")
	}
	oldSim, oldCfg := Sim, cfgMap
	Sim = false
	cfgMap = map[string]string{"dns.upstream": "127.0.0.53:53"}
	defer func() { Sim, cfgMap = oldSim, oldCfg }()
	e := newDNSEngine(exchangeDNS)
	if addresses := e.lookup("example.com"); len(addresses) == 0 {
		t.Fatal("existing resolver returned no positive-TTL A records", e.lastError)
	}
	q, _ := dnsRequest("example.com")
	reply, err := dnsQuestion(e.serve(q, nil), true)
	if err != nil || reply.RCode != 0 || len(reply.Answers) == 0 {
		t.Fatal("DNS proxy backend failed", reply, err)
	}
}

func TestDNSCNAMEBoundsAndUnrelatedAnswers(t *testing.T) {
	now := time.Unix(10000, 0)
	q, _ := dnsRequest("example.test")
	request, _ := dnsQuestion(q, false)
	alias, _ := dnsmessage.NewName("cdn.test.")
	cname := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: request.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 2}, Body: &dnsmessage.CNAMEResource{CNAME: alias}}
	packet := dnsTestResponse(q, cname, dnsTestA("cdn.test", "203.0.113.1", 600), dnsTestA("unrelated.test", "203.0.113.2", 600))
	m, err := dnsQuestion(packet, true)
	if err != nil {
		t.Fatal(err)
	}
	m.Additionals = []dnsmessage.Resource{dnsTestA("example.test", "203.0.113.3", 600)}
	addresses, _ := dnsAddresses(m, now)
	if len(addresses) != 1 || !addresses["203.0.113.1"].Equal(now.Add(2*time.Second)) {
		t.Fatal("CNAME TTL or answer owner ignored", addresses)
	}
	m.Answers = []dnsmessage.Resource{dnsTestA("example.test", "203.0.113.1", 0)}
	addresses, _ = dnsAddresses(m, now)
	if len(addresses) != 0 {
		t.Fatal("TTL zero cached")
	}
}

func TestDNSProxyValidatesAndWaitsForPolicy(t *testing.T) {
	q, _ := dnsRequest("sub.example.test")
	called := false
	e := newDNSEngine(func(packet []byte) ([]byte, error) {
		return dnsTestResponse(packet, dnsTestA("sub.example.test", "203.0.113.1", 60)), nil
	})
	e.tracked["example.test"] = time.Now()
	response, err := dnsQuestion(e.serve(q, func() error { called = true; return fmt.Errorf("route update blocked") }), true)
	if err != nil || !called || response.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("answer sent before policy", response, err)
	}
	response, err = dnsQuestion(e.serve(q, func() error { return nil }), true)
	if err != nil || len(response.Answers) != 1 {
		t.Fatal(response, err)
	}
	request, _ := dnsQuestion(q, false)
	request.Questions[0].Type = dnsmessage.TypeAAAA
	q6, _ := request.Pack()
	called = false
	response, err = dnsQuestion(e.serve(q6, func() error { called = true; return nil }), true)
	if err != nil || response.RCode != dnsmessage.RCodeRefused || called {
		t.Fatal("IPv6 policy not enforced", response, err)
	}
	e.exchange = func(packet []byte) ([]byte, error) {
		reply := dnsTestResponse(packet, dnsTestA("sub.example.test", "203.0.113.1", 60))
		binary.BigEndian.PutUint16(reply, 0)
		return reply, nil
	}
	request.ID = 123
	request.Questions[0].Type = dnsmessage.TypeA
	q, _ = request.Pack()
	response, _ = dnsQuestion(e.serve(q, nil), true)
	if response.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("mismatched ID accepted")
	}
	for _, bad := range []string{"1.1.1.1", "example.com:53", "127.0.0.1:5353", "127.0.0.1:15353", "1.1.1.1:domain", "[::1]:53", "0.0.0.0:53"} {
		if validDNSUpstream(bad) {
			t.Fatal("unsafe upstream accepted", bad)
		}
	}
}

func TestDNSExchangeTCPFallback(t *testing.T) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	address := tcp.Addr().String()
	udpAddress, _ := net.ResolveUDPAddr("udp4", address)
	udp, err := net.ListenUDP("udp4", udpAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	oldSim, oldCfg := Sim, cfgMap
	Sim = false
	cfgMap = map[string]string{"dns.upstream": address}
	defer func() { Sim, cfgMap = oldSim, oldCfg }()
	go func() {
		buffer := make([]byte, 4096)
		n, peer, err := udp.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		request, _ := dnsQuestion(buffer[:n], false)
		request.Response = true
		request.Truncated = true
		reply, _ := request.Pack()
		_, _ = udp.WriteToUDP(reply, peer)
	}()
	done := make(chan error, 1)
	go func() {
		c, err := tcp.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		var size [2]byte
		_, err = io.ReadFull(c, size[:])
		if err != nil {
			done <- err
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(size[:]))
		_, err = io.ReadFull(c, q)
		if err != nil {
			done <- err
			return
		}
		reply := dnsTestResponse(q, dnsTestA("example.test", "203.0.113.1", 60))
		binary.BigEndian.PutUint16(size[:], uint16(len(reply)))
		_, err = c.Write(append(size[:], reply...))
		done <- err
	}()
	query, _ := dnsRequest("example.test")
	reply, err := exchangeDNS(query)
	if err != nil {
		t.Fatal(err)
	}
	message, err := dnsQuestion(reply, true)
	original, _ := dnsQuestion(query, false)
	if err != nil || message.ID != original.ID || len(message.Answers) != 1 || message.Truncated {
		t.Fatal("TCP fallback failed", message, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type dnsResolveSys struct {
	Sys
	addresses []string
}

func (s *dnsResolveSys) Resolve(string) []string { return s.addresses }
func TestDNSUpdateKeepsPolicyRulesAndUnknownPortScope(t *testing.T) {
	s := transactionSetup(t)
	resolver := &dnsResolveSys{Sys: S, addresses: []string{"203.0.113.1"}}
	S = resolver
	if err := Apply("initial"); err != nil {
		t.Fatal(err)
	}
	s.commands = nil
	resolver.addresses = []string{"203.0.113.2"}
	if err := Apply("TTL update"); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range s.commands {
		if strings.HasPrefix(cmd, "ip rule ") || strings.HasPrefix(cmd, "ip route ") {
			t.Fatal("unchanged routing rules rewritten", cmd)
		}
	}
	rt.Profiles[0].Rules = []Rule{{ID: "domain", Match: "missing.test tcp:443", Exit: "meduza"}, {ID: "last", Last: true, Exit: "direct"}}
	resolver.addresses = nil
	script, _ := Compile()
	if strings.Contains(script, "tcp dport 443 ") {
		t.Fatal("failed DNS broadened a domain rule to every HTTPS connection", script)
	}
}

func TestDNSListenerUDPAndTCP(t *testing.T) {
	e := newDNSEngine(func(q []byte) ([]byte, error) {
		var answers []dnsmessage.Resource
		for i := 1; i <= 40; i++ {
			answers = append(answers, dnsTestA("example.test", fmt.Sprintf("203.0.113.%d", i), 60))
		}
		return dnsTestResponse(q, answers...), nil
	})
	reserve, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserve.Addr().String()
	reserve.Close()
	stop, err := startDNSListener(address, e, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	q, _ := dnsRequest("example.test")
	udp, err := net.Dial("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = udp.Write(q)
	buffer := make([]byte, 4096)
	n, err := udp.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	message, err := dnsQuestion(buffer[:n], true)
	if err != nil || !message.Truncated || n > 512 {
		t.Fatal("large UDP answer was not truncated", message, err)
	}
	tcp, err := net.Dial("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	_ = tcp.SetDeadline(time.Now().Add(3 * time.Second))
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(q)))
	_, _ = tcp.Write(append(size[:], q...))
	if _, err = io.ReadFull(tcp, size[:]); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err = io.ReadFull(tcp, body); err != nil {
		t.Fatal(err)
	}
	message, err = dnsQuestion(body, true)
	if err != nil || len(message.Answers) != 40 {
		t.Fatal("TCP answer incomplete", message, err)
	}
	stop()
	_, _ = tcp.Write(append([]byte{byte(len(q) >> 8), byte(len(q))}, q...))
	if _, err = tcp.Read(buffer); err == nil {
		t.Fatal("closed listener kept serving a TCP connection")
	}
	if _, err := startDNSListener("0.0.0.0:0", e, nil); err == nil {
		t.Fatal("public recursive resolver allowed")
	}
}

func TestDNSTTLRefreshIsolatedKernel(t *testing.T) {
	if os.Getenv("VPNGUARD_NETNS_TEST") != "1" {
		t.Skip("requires isolated Linux namespace")
	}
	oldS, oldSim, oldDir, oldCfg, oldMods, oldDNS, oldWg, oldRT := S, Sim, DataDir, cfgMap, Mods, routingDNS, wgMod.d, rt
	defer func() {
		S, Sim, DataDir, cfgMap, Mods, routingDNS, wgMod.d, rt = oldS, oldSim, oldDir, oldCfg, oldMods, oldDNS, oldWg, oldRT
	}()
	S, Sim, DataDir = realSys{}, true, t.TempDir()
	cfgMap = map[string]string{"net.wan": "lo", "net.pinFlows": "true"}
	Mods = nil
	for _, m := range []*flowTestExit{{id: "direct", iface: "lo", mark: 0x14}, {id: "meduza", iface: "vpn0", mark: 0x11, table: 101}, {id: "block", mark: 0x1f}} {
		m.setSt(0, true, "up", "")
		Mods = append(Mods, m)
	}
	wgMod.d = wgData{Priv: "loaded", Clients: []*WgClient{{IP: "192.168.15.2"}}}
	rt = Routes{Profiles: []Profile{{ID: "p1", Name: "test", Rules: []Rule{{ID: "domain", Match: "example.test", Exit: "meduza"}, {ID: "last", Last: true, Exit: "direct"}}}}, Clients: map[string]string{}, Overrides: map[string][]Rule{}, Policy: map[string]ExitPolicy{}}
	for _, iface := range []string{"lo", "wg_server", "vpn0"} {
		if iface != "lo" {
			kernelCommand(t, "ip", "link", "add", iface, "type", "dummy")
		}
		kernelCommand(t, "ip", "link", "set", iface, "up")
	}
	now := time.Unix(10000, 0)
	ip := "203.0.113.1"
	routingDNS = newDNSEngine(func(q []byte) ([]byte, error) { return dnsTestResponse(q, dnsTestA("example.test", ip, 1)), nil })
	routingDNS.now = func() time.Time { return now }
	applied, appliedIP = "", ""
	if err := Apply("DNS initial"); err != nil {
		t.Fatal(err)
	}
	rulesBefore, _ := run("ip", "-4", "rule", "show")
	sets, _ := run("nft", "list", "set", "inet", "vpnguard", "m_p1_domain")
	if !strings.Contains(sets, ip) {
		t.Fatal(sets)
	}
	now = now.Add(2 * time.Second)
	ip = "203.0.113.2"
	routingDNS.refresh()
	if err := Apply("DNS TTL"); err != nil {
		t.Fatal(err)
	}
	rulesAfter, _ := run("ip", "-4", "rule", "show")
	sets, _ = run("nft", "list", "set", "inet", "vpnguard", "m_p1_domain")
	if !strings.Contains(sets, ip) || strings.Contains(sets, "203.0.113.1") || rulesBefore != rulesAfter {
		t.Fatal("TTL refresh changed policy routing or kept expired addresses", sets, rulesBefore, rulesAfter)
	}
}
