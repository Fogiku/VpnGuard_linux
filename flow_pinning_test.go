package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

type flowTestExit struct {
	base
	id, iface   string
	mark, table int
}

func (m *flowTestExit) ID() string    { return m.id }
func (m *flowTestExit) Name() string  { return m.id }
func (m *flowTestExit) Color() string { return "" }
func (m *flowTestExit) Tick()         {}
func (m *flowTestExit) Exit() *Exit {
	return &Exit{Iface: m.iface, Mark: m.mark, Table: m.table, Block: m.id == "block"}
}

// Настоящий UDP-поток проходит через veth. Все интерфейсы создаются внутри
// отдельного network namespace; клиент имеет ещё одно временное пространство.
func TestFlowPinningIsolatedKernel(t *testing.T) {
	if os.Getenv("VPNGUARD_NETNS_TEST") != "1" {
		t.Skip("requires isolated Linux network namespace")
	}
	oldS, oldSim, oldData, oldCfg, oldMods, oldWg, oldRt := S, Sim, DataDir, cfgMap, Mods, wgMod.d, rt
	t.Cleanup(func() {
		S, Sim, DataDir, cfgMap, Mods, wgMod.d, rt = oldS, oldSim, oldData, oldCfg, oldMods, oldWg, oldRt
	})
	S, Sim, DataDir = realSys{}, false, t.TempDir()
	cfgMap = map[string]string{"net.pinFlows": "true", "net.wan": "out0"}
	Mods = nil
	for _, m := range []*flowTestExit{{id: "direct", iface: "out0", mark: 0x14}, {id: "meduza", iface: "out1", mark: 0x11, table: 101}, {id: "block", mark: 0x1f}} {
		m.setSt(0, true, "up", "")
		Mods = append(Mods, m)
	}
	wgMod.d = wgData{Priv: "loaded", Clients: []*WgClient{{IP: "10.253.0.2"}}}
	rt = Routes{Profiles: []Profile{{ID: "p1", Name: "test", Rules: []Rule{{ID: "all", Exit: "direct", Last: true}}}}, Clients: map[string]string{}, Overrides: map[string][]Rule{}, Policy: map[string]ExitPolicy{}}
	clientNS := exec.Command("unshare", "--net", "sleep", "90")
	if err := clientNS.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { clientNS.Process.Kill(); clientNS.Wait() }()
	pid := strconv.Itoa(clientNS.Process.Pid)
	// Ждём создания пространства клиента до переноса интерфейса.
	for i := 0; i < 100; i++ {
		own, _ := os.Readlink("/proc/self/ns/net")
		other, _ := os.Readlink("/proc/" + pid + "/ns/net")
		if other != "" && own != other {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	commands := [][]string{
		{"ip", "link", "add", "wg_server", "type", "veth", "peer", "name", "client0"},
		{"ip", "link", "set", "client0", "netns", pid},
		{"ip", "addr", "add", "10.253.0.1/24", "dev", "wg_server"}, {"ip", "link", "set", "wg_server", "up"},
		{"nsenter", "-t", pid, "-n", "ip", "addr", "add", "10.253.0.2/24", "dev", "client0"},
		{"nsenter", "-t", pid, "-n", "ip", "link", "set", "client0", "up"},
		{"nsenter", "-t", pid, "-n", "ip", "route", "add", "default", "via", "10.253.0.1"},
		{"ip", "link", "add", "out0", "type", "dummy"}, {"ip", "addr", "add", "192.0.2.1/24", "dev", "out0"}, {"ip", "link", "set", "out0", "up"},
		{"ip", "link", "add", "out1", "type", "dummy"}, {"ip", "addr", "add", "192.0.3.1/24", "dev", "out1"}, {"ip", "link", "set", "out1", "up"},
		{"ip", "route", "add", "default", "dev", "out0"}, {"ip", "route", "add", "default", "dev", "out1", "table", "101"},
		{"ip", "rule", "add", "fwmark", "0x11", "lookup", "101", "priority", "1101"},
		{"sysctl", "-w", "net.ipv4.ip_forward=1"},
	}
	for _, c := range commands {
		if out, code := run(c[0], c[1:]...); code != 0 {
			t.Fatalf("%v: %s", c, out)
		}
	}
	apply := func() {
		t.Helper()
		script, _ := Compile()
		if out, code := S.Run(5*time.Second, script, "nft", "-f", "-"); code != 0 {
			t.Fatalf("compile: %s\n%s", out, script)
		}
	}
	apply()
	probe := `table inet pin_probe {
 chain foreign_bits { type filter hook prerouting priority -151; policy accept; iifname "wg_server" ct mark set ct mark | 0x80000001; }
	 chain count { type filter hook forward priority 10; policy accept;
  udp sport 41001 meta mark 0x14 counter comment "old_direct"
  udp sport 41001 meta mark 0x11 counter comment "old_moved"
  udp sport 41002 meta mark 0x11 counter comment "new_vpn"
  udp sport {41001,41002} ct mark & 0xff00ffff != 0x80000001 counter comment "foreign_bits_lost"
 }
}
`
	if out, code := S.Run(time.Second, probe, "nft", "-f", "-"); code != 0 {
		t.Fatal(out)
	}
	python := `import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.253.0.2',41001))
s.sendto(b'first',('198.51.100.5',9000));print('sent',flush=True)
sys.stdin.readline()
s.sendto(b'same flow',('198.51.100.5',9000))
n=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);n.bind(('10.253.0.2',41002));n.sendto(b'new flow',('198.51.100.5',9000))
`
	sender := exec.Command("nsenter", "-t", pid, "-n", "python3", "-u", "-c", python)
	stdin, err := sender.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := sender.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = sender.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { sender.Process.Kill(); sender.Wait() }()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if strings.TrimSpace(line) != "sent" {
			t.Fatal("client did not send first packet")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client timeout")
	}
	// Дожидаемся первого пакета в цепочке forward, затем меняем политику.
	readCounters := func() map[string]float64 {
		out, code := run("nft", "-j", "list", "table", "inet", "pin_probe")
		if code != 0 {
			t.Fatal(out)
		}
		var doc struct {
			Nftables []struct {
				Rule *struct {
					Comment string
					Expr    []map[string]any
				}
			}
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatal(err)
		}
		counts := map[string]float64{}
		for _, v := range doc.Nftables {
			if v.Rule != nil {
				for _, expr := range v.Rule.Expr {
					if c, ok := expr["counter"].(map[string]any); ok {
						counts[v.Rule.Comment], _ = c["packets"].(float64)
					}
				}
			}
		}
		return counts
	}
	for i := 0; i < 100 && readCounters()["old_direct"] < 1; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if readCounters()["old_direct"] != 1 {
		t.Fatal("first UDP packet did not use direct")
	}
	rt.Profiles[0].Rules[0].Exit = "meduza"
	apply()
	io.WriteString(stdin, "continue\n")
	stdin.Close()
	for i := 0; i < 100 && readCounters()["new_vpn"] < 1; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	c := readCounters()
	if c["old_direct"] != 2 || c["old_moved"] != 0 || c["new_vpn"] != 1 || c["foreign_bits_lost"] != 0 {
		t.Fatal(fmt.Sprintf("flow pinning failed: %v", c))
	}
	mod("meduza").(*flowTestExit).setSt(2, false, "down", "")
	apply()
	// То же UDP-соединение к отказавшему VPN должно блокироваться до следующей цепочки.
	out, code := run("nsenter", "-t", pid, "-n", "python3", "-c", `import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.253.0.2',41002));s.sendto(b'failed exit',('198.51.100.5',9000))`)
	if code != 0 {
		t.Fatal(out)
	}
	time.Sleep(150 * time.Millisecond)
	if readCounters()["new_vpn"] != 1 {
		t.Fatal("pinned flow passed forward after exit failure")
	}
}
