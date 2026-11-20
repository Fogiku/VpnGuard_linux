package main

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDNSClientSettingsAndACL(t *testing.T) {
	old := cfgMap
	defer func() { cfgMap = old }()
	cfgMap = map[string]string{}
	for _, overrides := range []map[string]string{
		{"dns.lanAddress": "0.0.0.0", "dns.allowLAN": "192.168.1.0/24"},
		{"dns.lanAddress": "1.1.1.1", "dns.allowLAN": "192.168.1.0/24"},
		{"dns.lanAddress": "192.168.1.66"},
		{"dns.allowLAN": "0.0.0.0/0"}, {"dns.allowLAN": "10.0.0.0/7"}, {"dns.allowLAN": "172.0.0.0/11"}, {"dns.allowLAN": "192.168.0.0/15"}, {"dns.allowLAN": "::/0"},
		{"dns.serveWG": "1"}, {"dns.serveWG": "true", "dns.upstream": "10.253.0.1:53"},
	} {
		if _, err := readDNSClientSettings(overrides); err == nil {
			t.Fatal("invalid DNS access accepted", overrides)
		}
	}
	s, err := readDNSClientSettings(map[string]string{"dns.serveWG": "true", "dns.lanAddress": "192.168.1.66", "dns.allowLAN": "192.168.100.0/24,192.168.1.7/24"})
	if err != nil {
		t.Fatal(err)
	}
	plans, err := s.plans(true)
	if err != nil || len(plans) != 2 {
		t.Fatal(plans, err)
	}
	if !plans[0].allow(net.ParseIP("10.253.0.2")) || plans[0].allow(net.ParseIP("192.168.1.2")) || !plans[1].allow(net.ParseIP("192.168.100.200")) || plans[1].allow(net.ParseIP("192.168.2.2")) || plans[1].allow(net.ParseIP("2001:db8::2")) {
		t.Fatal("ACL scope incorrect")
	}
}

func TestDNSRevokesExistingTCPAccess(t *testing.T) {
	e := newDNSEngine(func(q []byte) ([]byte, error) {
		return dnsTestResponse(q, dnsTestA("example.test", "203.0.113.1", 60)), nil
	})
	reserve, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserve.Addr().String()
	reserve.Close()
	policy := newDNSAccessPolicy(func(ip net.IP) bool { return ip.IsLoopback() })
	stop, err := startDNSListenerWithAccess(address, "", policy, e, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	c, err := net.Dial("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	q, _ := dnsRequest("example.test")
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(q)))
	frame := append(size[:], q...)
	if _, err = c.Write(frame); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(c, size[:]); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err = io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	policy.set(func(net.IP) bool { return false })
	_, _ = c.Write(frame)
	if _, err = c.Read(make([]byte, 16)); err == nil {
		t.Fatal("revoked TCP session still received answers")
	}
	e.mu.Lock()
	queries := e.queries
	e.mu.Unlock()
	if queries != 1 {
		t.Fatal("revoked query reached upstream", queries)
	}
}

func TestDNSFailedReconfigurePreservesOldListeners(t *testing.T) {
	oldDNS := routingDNS
	defer func() { routingDNS = oldDNS }()
	routingDNS = newDNSEngine(func(q []byte) ([]byte, error) { return dnsTestResponse(q), nil })
	busy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	closed := false
	oldPlan := dnsClientPlan{Kind: "test", Address: "127.0.0.1:1"}
	old := &dnsClientListener{plan: oldPlan, policy: newDNSAccessPolicy(func(net.IP) bool { return true }), stop: func() { closed = true }}
	m := &dnsModule{clients: map[string]*dnsClientListener{oldPlan.key(): old}}
	_, err = m.prepareClients([]dnsClientPlan{oldPlan, {Kind: "test", Address: busy.Addr().String()}})
	if err == nil || closed || m.clients[oldPlan.key()] != old || !old.policy.allows(net.ParseIP("127.0.0.1")) {
		t.Fatal("failed reconfigure damaged active listener", err)
	}
}

func TestDNSWGExportDoesNotSyncServer(t *testing.T) {
	setup(t)
	oldSim := Sim
	defer func() { Sim = oldSim }()
	Sim = true
	if err := setCfg("dns.serveWG", "true"); err != nil {
		t.Fatal(err)
	}
	before := wgMod.conf(false)
	m := &dnsModule{}
	if _, err := m.Do("wg-profiles", nil); err != nil {
		t.Fatal(err)
	}
	if before != wgMod.conf(false) {
		t.Fatal("server configuration changed")
	}
	client := wgMod.Clients()[0]
	if !strings.Contains(wgMod.clientConf(&client), "DNS = "+wgMod.subnet()+".1\n") {
		t.Fatal("export did not use gateway DNS")
	}
}

func TestDNSInterfaceAccessIsolatedKernel(t *testing.T) {
	if os.Getenv("VPNGUARD_NETNS_TEST") != "1" {
		t.Skip("requires isolated Linux namespace")
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if self == "" || self == host {
		t.Fatal("test must run in a separate namespace")
	}
	oldS := S
	S = realSys{}
	defer func() { S = oldS }()
	client := exec.Command("unshare", "--net", "sleep", "90")
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { client.Process.Kill(); client.Wait() }()
	pid := strconv.Itoa(client.Process.Pid)
	for i := 0; i < 100; i++ {
		other, _ := os.Readlink("/proc/" + pid + "/ns/net")
		if other != "" && other != self {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, pair := range [][2]string{{"lan0", "client0"}, {"other0", "otherclient0"}} {
		kernelCommand(t, "ip", "link", "add", pair[0], "type", "veth", "peer", "name", pair[1])
		kernelCommand(t, "ip", "link", "set", pair[1], "netns", pid)
		kernelCommand(t, "ip", "link", "set", pair[0], "up")
		kernelCommand(t, "nsenter", "-t", pid, "-n", "ip", "link", "set", pair[1], "up")
	}
	for _, address := range []string{"192.168.60.1/24", "192.168.61.1/24"} {
		kernelCommand(t, "ip", "addr", "add", address, "dev", "lan0")
	}
	for _, address := range []string{"192.168.60.2/24", "192.168.61.2/24"} {
		kernelCommand(t, "nsenter", "-t", pid, "-n", "ip", "addr", "add", address, "dev", "client0")
	}
	kernelCommand(t, "ip", "addr", "add", "192.168.62.1/24", "dev", "other0")
	kernelCommand(t, "nsenter", "-t", pid, "-n", "ip", "addr", "add", "192.168.62.2/24", "dev", "otherclient0")
	for _, iface := range []string{"all", "default", "lan0", "other0"} {
		kernelCommand(t, "sysctl", "-w", "net.ipv4.conf."+iface+".rp_filter=0")
	}
	kernelCommand(t, "ip", "-6", "addr", "add", "fd00:60::1/64", "dev", "lan0", "nodad")
	kernelCommand(t, "nsenter", "-t", pid, "-n", "ip", "-6", "addr", "add", "fd00:60::2/64", "dev", "client0", "nodad")
	e := newDNSEngine(func(q []byte) ([]byte, error) {
		return dnsTestResponse(q, dnsTestA("example.test", "203.0.113.1", 60)), nil
	})
	_, network, _ := net.ParseCIDR("192.168.60.0/24")
	policy := newDNSAccessPolicy(func(ip net.IP) bool { return network.Contains(ip) })
	stop, err := startDNSListenerWithAccess("192.168.60.1:5300", "lan0", policy, e, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	script := `import socket,struct,sys
source,transport,mode=sys.argv[1:]
name=b'\x07example\x04test\x00';kind=28 if mode=='aaaa' else 1
packet=struct.pack('!HHHHHH',1234,256,1,0,0,0)+name+struct.pack('!HH',kind,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if transport=='udp' else socket.SOCK_STREAM);s.settimeout(.7);s.bind((source,0))
try:
 if transport=='udp': s.sendto(packet,('192.168.60.1',5300));reply=s.recv(4096)
 else:
  s.connect(('192.168.60.1',5300));s.sendall(struct.pack('!H',len(packet))+packet);size=s.recv(2)
  if len(size)!=2: raise ConnectionError('closed')
  n=struct.unpack('!H',size)[0];reply=b''
  while len(reply)<n:
   part=s.recv(n-len(reply))
   if not part: raise ConnectionError('closed')
   reply+=part
 if mode=='deny': raise AssertionError('unauthorized DNS reply')
 assert struct.unpack('!H',reply[2:4])[0]&15==(5 if mode=='aaaa' else 0)
except (OSError,ConnectionError):
 if mode!='deny': raise
finally: s.close()`
	probe := func(source, transport, mode string) {
		t.Helper()
		out, err := exec.Command("nsenter", "-t", pid, "-n", "python3", "-c", script, source, transport, mode).CombinedOutput()
		if err != nil {
			t.Fatalf("DNS %s %s %s: %s %v", source, transport, mode, out, err)
		}
	}
	probe("192.168.60.2", "udp", "ok")
	probe("192.168.60.2", "tcp", "ok")
	probe("192.168.60.2", "udp", "aaaa")
	probe("192.168.61.2", "udp", "deny")
	probe("192.168.61.2", "tcp", "deny")
	kernelCommand(t, "nsenter", "-t", pid, "-n", "ip", "route", "add", "192.168.60.1/32", "via", "192.168.62.1", "dev", "otherclient0")
	probe("192.168.60.2", "udp", "deny")
	probe("192.168.60.2", "tcp", "deny")
	kernelCommand(t, "nsenter", "-t", pid, "-n", "ping", "-6", "-n", "-c", "1", "-W", "1", "fd00:60::1")
	v6 := `import socket
s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.settimeout(1)
try:
 s.connect(('fd00:60::1',5300));raise AssertionError('unexpected IPv6 DNS listener')
except OSError: pass
finally: s.close()`
	if out, err := exec.Command("nsenter", "-t", pid, "-n", "python3", "-c", v6).CombinedOutput(); err != nil {
		t.Fatal(string(out), err)
	}
	e.mu.Lock()
	queries := e.queries
	e.mu.Unlock()
	if queries != 2 {
		t.Fatal("denied queries reached upstream", queries)
	}
}
