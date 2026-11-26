package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestZapretTrialSelection(t *testing.T) {
	setup(t)
	m := mod("zapret").(*zapret2)
	if _, err := m.Do("trial", map[string]string{"preset": "--daemon"}); err == nil {
		t.Fatal("accepted unknown preset")
	}
	for _, preset := range builtinZapretStrategies() {
		msg, err := m.Do("trial", map[string]string{"preset": preset.Name})
		if err != nil || !strings.Contains(msg, fmt.Sprintf("%x", sha256.Sum256([]byte(preset.Args+"\n")))) || !strings.Contains(msg, "Симулятор") {
			t.Fatal(msg, err)
		}
	}
}

func TestZapretTrialLinux(t *testing.T) {
	if os.Getenv("VPNGUARD_TEST_NFQWS2_TRIAL") != "1" {
		t.Skip("requires disposable Linux namespace and installed zapret2")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := os.Readlink("/proc/1/ns/net")
	if err != nil || current == initial {
		t.Fatal("disposable parent network namespace required", err)
	}
	oldSys, oldSim := S, Sim
	S, Sim = realSys{}, false
	defer func() { S, Sim = oldSys, oldSim }()
	baseline := exec.Command("/opt/zapret2/nfq2/nfqws2", "--qnum=200")
	baseline.Dir = "/opt/zapret2"
	baseline.Stderr = os.Stderr
	if err := baseline.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { baseline.Process.Kill(); baseline.Wait() }()
	ownsQueue := func() bool {
		raw, _ := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
		for _, row := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(row)
			if len(fields) >= 2 && fields[0] == "200" && fields[1] == strconv.Itoa(baseline.Process.Pid) {
				return true
			}
		}
		return false
	}
	deadline := time.Now().Add(5 * time.Second)
	for !ownsQueue() {
		if time.Now().After(deadline) {
			t.Fatal("baseline queue unavailable")
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, p := range builtinZapretStrategies() {
		msg, err := trialZapretPreset(p.Name, "http")
		if err != nil || !strings.Contains(msg, "оба контрольных HTTP-ответа") || !ownsQueue() {
			t.Fatal(msg, err)
		}
		t.Log(msg)
	}
	// A candidate that fails to parse must release its namespace without touching the baseline.
	out, code := S.Run(12*time.Second, "", "unshare", "--net", "--pid", "--fork", "--kill-child=KILL", "--mount-proc", "--", "python3", "-I", "-c", zapretTrialWorker, current, "startup", "--qnum=200", "--lua-init=@lua/missing-test-script.lua")
	if code == 0 || !strings.Contains(out, "до готовности") || !ownsQueue() {
		t.Fatalf("failed candidate: %d %s", code, out)
	}

}
