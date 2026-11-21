package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Run on the two-path TCP test topology so the receiver can report the actual NAT address.
func checkUDPRecovery(t *testing.T, client, server string, apply func()) {
	const counter = `table inet udp_recovery {
chain egress { type filter hook postrouting priority 150; policy accept;
udp sport 41008 oifname "out0" counter comment "wrong_exit"
}
}
`
	if out, code := S.Run(5*time.Second, counter, "nft", "-f", "-"); code != 0 {
		t.Fatal(out)
	}
	_, serverLine := kernelPython(t, server, `import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('198.51.100.5',9002))
print('ready',flush=True)
while True:
    data,peer=s.recvfrom(1024)
    s.sendto(peer[0].encode()+b'|'+data,peer)
`)
	if serverLine() != "ready" {
		t.Fatal("UDP receiver failed")
	}
	rt.Profiles[0].Rules[0].Exit = "meduza"
	apply()
	input, line := kernelPython(t, client, `import socket,sys,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('10.253.0.2',41008))
s.connect(('198.51.100.5',9002))
sequence=0
for command in sys.stdin:
    count,timeout=map(int,command.split())
    s.settimeout(timeout/1000)
    confirmed=0
    first=-1
    start=time.monotonic()
    for _ in range(count):
        sequence+=1
        data=str(sequence).encode()
        s.send(data)
        try:
            reply=s.recv(1024)
        except socket.timeout:
            continue
        if reply!=b'192.0.3.1|'+data: raise RuntimeError('wrong exit or sequence')
        if first<0: first=round((time.monotonic()-start)*1000)
        confirmed+=1
        time.sleep(.01)
    print(confirmed,first,flush=True)
`)
	phase := func(n, timeout, want int) {
		t.Helper()
		if _, err := fmt.Fprintf(input, "%d %d\n", n, timeout); err != nil {
			t.Fatal(err)
		}
		var received, first int
		if _, err := fmt.Sscan(line(), &received, &first); err != nil || received != want {
			t.Fatalf("UDP confirmed %d/%d, expected %d: %v", received, n, want, err)
		}
		t.Logf("confirmed %d/%d, first reply after batch start %d ms (-1 means none)", received, n, first)
	}
	phase(100, 1000, 100)
	// Remove the tunnel device's route while its module still reports Up.
	kernelCommand(t, "ip", "route", "del", "default", "table", "101")
	fallback, code := run("ip", "route", "get", "198.51.100.5", "mark", "0x11")
	if code != 0 || !strings.Contains(fallback, "dev out0") {
		t.Fatalf("expected kernel fallback to WAN: %s", fallback)
	}
	phase(20, 50, 0)
	kernelCommand(t, "ip", "route", "add", "default", "via", "192.0.3.2", "table", "101")
	phase(100, 1000, 100)
	kernelCommand(t, "ip", "link", "set", "out1", "down")
	phase(20, 50, 0)
	kernelCommand(t, "ip", "link", "set", "out1", "up")
	kernelCommand(t, "ip", "route", "replace", "default", "via", "192.0.3.2", "table", "101")
	phase(100, 1000, 100)
	mod("meduza").(*flowTestExit).setSt(2, false, "down", "")
	rt.Profiles[0].Rules[0].Exit = "direct"
	apply()
	phase(20, 50, 0)
	mod("meduza").(*flowTestExit).setSt(0, true, "up", "")
	apply()
	phase(100, 1000, 100)
	out, code := run("nft", "list", "chain", "inet", "udp_recovery", "egress")
	if code != 0 || !strings.Contains(out, `counter packets 0 bytes 0 comment "wrong_exit"`) {
		t.Fatalf("unexpected direct egress: %s", out)
	}
}
