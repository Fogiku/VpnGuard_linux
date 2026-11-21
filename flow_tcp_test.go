package main

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func kernelNamespace(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("unshare", "--net", "sleep", "600")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	pid := strconv.Itoa(cmd.Process.Pid)
	for i := 0; i < 100; i++ {
		own, _ := os.Readlink("/proc/self/ns/net")
		child, _ := os.Readlink("/proc/" + pid + "/ns/net")
		if child != "" && child != own {
			return pid
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("namespace creation timed out")
	return ""
}

func kernelCommand(t *testing.T, args ...string) {
	t.Helper()
	if out, code := run(args[0], args[1:]...); code != 0 {
		t.Fatalf("%v: %s", args, out)
	}
}

func kernelPython(t *testing.T, pid, script string) (io.WriteCloser, func() string) {
	t.Helper()
	cmd := exec.Command("nsenter", "-t", pid, "-n", "python3", "-u", "-c", script)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Process.Kill(); cmd.Wait() })
	lines := make(chan string, 16)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	return stdin, func() string {
		t.Helper()
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("python exited: %s", stderr.String())
			}
			return line
		case <-time.After(10 * time.Second):
			t.Fatalf("python timeout: %s", stderr.String())
			return ""
		}
	}
}

func TestTcpFlowPinningIsolatedKernel(t *testing.T) {
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
	client, server := kernelNamespace(t), kernelNamespace(t)
	commands := [][]string{
		{"ip", "link", "add", "wg_server", "type", "veth", "peer", "name", "client0"}, {"ip", "link", "set", "client0", "netns", client},
		{"ip", "addr", "add", "10.253.0.1/24", "dev", "wg_server"}, {"ip", "link", "set", "wg_server", "up"},
		{"nsenter", "-t", client, "-n", "ip", "addr", "add", "10.253.0.2/24", "dev", "client0"}, {"nsenter", "-t", client, "-n", "ip", "link", "set", "client0", "up"}, {"nsenter", "-t", client, "-n", "ip", "route", "add", "default", "via", "10.253.0.1"},
		{"ip", "link", "add", "out0", "type", "veth", "peer", "name", "server0"}, {"ip", "link", "set", "server0", "netns", server},
		{"ip", "addr", "add", "192.0.2.1/24", "dev", "out0"}, {"ip", "link", "set", "out0", "up"},
		{"nsenter", "-t", server, "-n", "ip", "addr", "add", "192.0.2.2/24", "dev", "server0"}, {"nsenter", "-t", server, "-n", "ip", "link", "set", "server0", "up"},
		{"ip", "link", "add", "out1", "type", "veth", "peer", "name", "server1"}, {"ip", "link", "set", "server1", "netns", server},
		{"ip", "addr", "add", "192.0.3.1/24", "dev", "out1"}, {"ip", "link", "set", "out1", "up"},
		{"nsenter", "-t", server, "-n", "ip", "addr", "add", "192.0.3.2/24", "dev", "server1"}, {"nsenter", "-t", server, "-n", "ip", "link", "set", "server1", "up"},
		{"nsenter", "-t", server, "-n", "ip", "addr", "add", "198.51.100.5/32", "dev", "lo"}, {"nsenter", "-t", server, "-n", "ip", "link", "set", "lo", "up"},
		{"ip", "route", "add", "default", "via", "192.0.2.2"}, {"ip", "route", "add", "default", "via", "192.0.3.2", "table", "101"}, {"ip", "rule", "add", "fwmark", "0x11", "lookup", "101", "priority", "1101"},
		{"sysctl", "-w", "net.ipv4.ip_forward=1"},
	}
	for _, cmd := range commands {
		kernelCommand(t, cmd...)
	}
	apply := func() {
		t.Helper()
		script, _ := Compile()
		if out, code := S.Run(5*time.Second, script, "nft", "-f", "-"); code != 0 {
			t.Fatal(out)
		}
	}
	apply()
	if os.Getenv("VPNGUARD_UDP_RECOVERY") == "1" {
		t.Run("udp_recovery", func(t *testing.T) { checkUDPRecovery(t, client, server, apply) })
	}
	_, serverLine := kernelPython(t, server, `import socket,threading
def echo(c,peer):
 with c:
  while True:
   data=c.recv(4096)
   if not data:return
   c.sendall(peer[0].encode()+b'|'+data)
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('198.51.100.5',9001));s.listen();print('ready',flush=True)
while True:
 c,p=s.accept();threading.Thread(target=echo,args=(c,p),daemon=True).start()
`)
	if serverLine() != "ready" {
		t.Fatal("echo server not ready")
	}
	if os.Getenv("VPNGUARD_FLOW_LOAD") == "1" {
		checkEstablishedFlowsUnderLoad(t, client, apply)
	}
	input, line := kernelPython(t, client, `import socket,sys
def connect(port):
 s=socket.socket();s.settimeout(5);s.bind(('10.253.0.2',port));s.connect(('198.51.100.5',9001));return s
def receive(s,size):
 data=b''
 while len(data)<size:
  part=s.recv(size-len(data))
  if not part:raise RuntimeError('TCP closed')
  data+=part
 return data.decode()
def exchange(s,data):
 s.sendall(data);print(receive(s,len(data)+10),flush=True)
old=connect(41003);exchange(old,b'before')
sys.stdin.readline();exchange(old,b'after');new=connect(41004);exchange(new,b'new')
sys.stdin.readline();new.settimeout(0.5);new.sendall(b'during-down')
try:print('unexpected:'+new.recv(4096).decode(),flush=True)
except socket.timeout:print('blocked',flush=True)
sys.stdin.readline();new.settimeout(5);print(receive(new,len(b'during-down')+10),flush=True);exchange(old,b'old-still-alive')
`)
	expect := func(want string) {
		t.Helper()
		if got := line(); got != want {
			t.Fatalf("want %q, got %q", want, got)
		}
	}
	expect("192.0.2.1|before")
	rt.Profiles[0].Rules[0].Exit = "meduza"
	apply()
	io.WriteString(input, "change\n")
	expect("192.0.2.1|after")
	expect("192.0.3.1|new")
	mod("meduza").(*flowTestExit).setSt(2, false, "down", "")
	apply()
	io.WriteString(input, "down\n")
	expect("blocked")
	mod("meduza").(*flowTestExit).setSt(0, true, "up", "")
	apply()
	io.WriteString(input, "up\n")
	expect("192.0.3.1|during-down")
	expect("192.0.2.1|old-still-alive")
	// Локальная сеть имеет приоритет перед VPN и состоянием внешнего интернета.
	cfgMap["net.localNetworks"] = "198.51.100.5/32"
	mod("direct").(*flowTestExit).setSt(2, false, "internet down", "")
	apply()
	output, code := run("nsenter", "-t", client, "-n", "python3", "-c", `import socket;s=socket.socket();s.settimeout(3);s.bind(('10.253.0.2',41005));s.connect(('198.51.100.5',9001));s.sendall(b'local');print(s.recv(4096).decode())`)
	if code != 0 || strings.TrimSpace(output) != "192.0.2.1|local" {
		t.Fatalf("local bypass: %s", output)
	}
	probe := `table inet management_probe {
 chain count { type filter hook postrouting priority 150; policy accept; tcp sport 41006 oifname "out0" counter; }
}
`
	if out, code := S.Run(time.Second, probe+"\n", "nft", "-f", "-"); code != 0 {
		t.Fatal(out)
	}
	// Даже сокет с VPN-меткой должен отправить управление через main.
	kernelCommand(t, "python3", "-c", `import socket;s=socket.socket();s.settimeout(3);s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,0x11);s.bind(('192.0.2.1',41006));s.connect(('198.51.100.5',9001));s.sendall(b'management');assert s.recv(4096)`)
	counts, _ := run("nft", "list", "table", "inet", "management_probe")
	match := regexp.MustCompile(`counter packets ([0-9]+)`).FindStringSubmatch(counts)
	if len(match) != 2 || match[1] == "0" {
		t.Fatalf("management output did not use main: %s", counts)
	}
}

// Exercise existing sockets while the default for newly classified connections changes.
func checkEstablishedFlowsUnderLoad(t *testing.T, client string, apply func()) {
	t.Helper()
	input, line := kernelPython(t, client, `import concurrent.futures, socket, sys, threading, time
ready = threading.Barrier(5, timeout=6)
stop = threading.Event()
def stream():
    with socket.create_connection(('198.51.100.5', 9001), timeout=4) as sock:
        expected = b'192.0.2.1|x'
        count = 0
        while not stop.is_set():
            sock.sendall(b'x')
            response = bytearray()
            while len(response) < len(expected):
                part = sock.recv(len(expected)-len(response))
                if not part: raise RuntimeError('closed TCP connection')
                response.extend(part)
            if response != expected: raise RuntimeError('established flow changed exit')
            count += 1
            if count == 1: ready.wait()
            time.sleep(0.02)
        return count
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    workers = [pool.submit(stream) for _ in range(4)]
    ready.wait()
    print('ready', flush=True)
    sys.stdin.readline()
    stop.set()
    print(' '.join(str(w.result()) for w in workers), flush=True)
`)
	if line() != "ready" {
		t.Fatal("TCP load did not start")
	}
	start := time.Now()
	for i := 0; i < 12; i++ {
		for _, exit := range []string{"meduza", "direct"} {
			rt.Profiles[0].Rules[0].Exit = exit
			apply()
			time.Sleep(time.Second)
		}
	}
	if _, err := io.WriteString(input, "stop\n"); err != nil {
		t.Fatal(err)
	}
	counts := strings.Fields(line())
	if len(counts) != 4 {
		t.Fatalf("missing stream results: %v", counts)
	}
	for _, value := range counts {
		n, err := strconv.Atoi(value)
		if err != nil || n < 24 {
			t.Fatalf("insufficient confirmed exchanges: %v", counts)
		}
	}
	t.Logf("24 policy changes over %s, acknowledged TCP exchanges per socket: %v", time.Since(start).Round(time.Millisecond), counts)
}
