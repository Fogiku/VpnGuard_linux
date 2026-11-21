package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

type eventTestRunner struct {
	line   string
	silent bool
}

type eventModuleSys struct{ flowTestSys }

func (s *eventModuleSys) FlowEvents(ctx context.Context, program string, line func(string) error) error {
	return (eventTestRunner{line: `{"epoch":"0123456789abcdef0123456789abcdef","rows":[]}`}).FlowEvents(ctx, program, line)
}
func TestEventModuleDisableReapsWorker(t *testing.T) {
	setup(t)
	oldS, oldSim := S, Sim
	defer func() { S = oldS; Sim = oldSim }()
	S = &eventModuleSys{flowTestSys{Sys: S, output: `{"rows":[],"seen":0,"truncated":false}`}}
	Sim = false
	m := &flowModule{}
	defer func() {
		if m.events != nil {
			m.events.stop()
		}
	}()
	if err := m.Set("flows.enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if m.events != nil {
		t.Fatal("events enabled by default")
	}
	if err := m.Set("flows.eventsEnabled", "true"); err != nil {
		t.Fatal(err)
	}
	waitEventReady(t, m.events)
	worker := m.events
	if err := m.Set("flows.enabled", "false"); err != nil {
		t.Fatal(err)
	}
	if m.events != nil {
		t.Fatal("disabled module retained worker")
	}
	select {
	case <-worker.done:
	default:
		t.Fatal("disabled worker not reaped")
	}
	if worker.summary() != nil {
		t.Fatal("disabled worker retained evidence")
	}
}

func (r eventTestRunner) FlowEvents(ctx context.Context, program string, line func(string) error) error {
	if !strings.Contains(program, "stream_events()") {
		panic("missing event program")
	}
	if !r.silent {
		if err := line(r.line); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return ctx.Err()
}
func waitEventReady(t *testing.T, s *flowEventSession) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.summary() != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("event subscription did not become ready")
}
func TestEventSessionCancelAndInvalidFrame(t *testing.T) {
	s := startFlowEvents(eventTestRunner{line: `{"epoch":"0123456789abcdef0123456789abcdef","rows":[]}`})
	waitEventReady(t, s)
	s.stop()
	if s.summary() != nil {
		t.Fatal("cancel retained continuity")
	}
	s = startFlowEvents(eventTestRunner{line: `{"epoch":"bad","rows":[]}`})
	select {
	case <-s.done:
	case <-time.After(time.Second):
		t.Fatal("invalid frame not rejected")
	}
	if s.summary() != nil {
		t.Fatal("invalid frame trusted")
	}
}
func TestEventSessionHeartbeatTimeout(t *testing.T) {
	s := startFlowEvents(eventTestRunner{silent: true})
	defer s.stop()
	select {
	case <-s.done:
	case <-time.After(6 * time.Second):
		t.Fatal("watchdog did not cancel silent child")
	}
	if s.summary() != nil {
		t.Fatal("silent observer trusted")
	}
}
func TestEventLiveEmbeddedProcess(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("VPNGUARD_TEST_FLOW_READ") != "1" {
		t.Skip("explicit Linux conntrack opt-in required")
	}
	s := startFlowEvents(realSys{})
	defer s.stop()
	waitEventReady(t, s)
	time.Sleep(1200 * time.Millisecond)
	if s.summary() == nil {
		t.Fatal("real heartbeat stopped")
	}
	s.stop()
	if s.summary() != nil {
		t.Fatal("real child retained continuity")
	}
}

func TestEventModuleLive(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("VPNGUARD_TEST_FLOW_READ") != "1" {
		t.Skip("explicit Linux conntrack opt-in required")
	}
	setup(t)
	oldS, oldSim := S, Sim
	defer func() { S = oldS; Sim = oldSim }()
	S, Sim = realSys{}, false
	m := &flowModule{}
	defer func() {
		if m.events != nil {
			m.events.stop()
		}
	}()
	if err := m.Set("flows.enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if err := m.Set("flows.eventsEnabled", "true"); err != nil {
		t.Fatal(err)
	}
	waitEventReady(t, m.events)
	worker := m.events
	if err := m.Set("flows.enabled", "false"); err != nil {
		t.Fatal(err)
	}
	if m.events != nil || len(m.rows) != 0 {
		t.Fatal("disable retained data")
	}
	select {
	case <-worker.done:
	default:
		t.Fatal("real child not reaped")
	}
}

func TestLifecycleLoopbackUDP(t *testing.T) {
	if os.Getenv("VPNGUARD_NETNS_TEST") != "1" || runtime.GOOS != "linux" {
		t.Skip("requires an isolated Linux network namespace")
	}
	// Install a conntrack hook inside the disposable namespace.
	const rules = "table inet lifecycle_probe { chain output { type filter hook output priority filter; ct state new counter; }\n}\n"
	if out, code := (realSys{}).Run(3*time.Second, rules, "nft", "-f", "-"); code != 0 {
		t.Fatal(out)
	}
	t.Cleanup(func() { (realSys{}).Run(3*time.Second, "", "nft", "delete", "table", "inet", "lifecycle_probe") })
	s := startFlowEvents(realSys{})
	defer s.stop()
	waitEventReady(t, s)
	before := s.summary()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.WriteToUDP([]byte("test"), conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		now := s.summary()
		if now != nil && now.Epoch == before.Epoch && now.Opened > before.Opened && now.Active > before.Active {
			t.Logf("observed real UDP NEW: opened %d, active %d", now.Opened, now.Active)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("loopback UDP NEW not reported")
}

func TestLifecycleDiagnosticSummary(t *testing.T) {
	setup(t)
	token := newToken()
	setCfg("remote.token", token)
	setCfg("remote.enabled", "true")
	setCfg("remote.until", time.Now().Add(time.Hour).Format(time.RFC3339))
	old := flowsMod
	flowsMod = &flowModule{}
	t.Cleanup(func() { flowsMod = old })
	const path = "/v1/diagnostics/flow-lifecycle"
	const epoch = "0123456789abcdef0123456789abcdef"
	worker := startFlowEvents(eventTestRunner{line: `{"epoch":"` + epoch + `","rows":[],"opened":8,"completed":8,"unmatchedUpdates":2,"unmatchedDestroys":1}`})
	defer worker.stop()
	flowsMod.events = worker
	waitEventReady(t, worker)
	code, body := remoteGet(path, token, "127.0.0.1")
	var page struct {
		SchemaVersion int               `json:"schemaVersion"`
		Observation   *lifecycleSummary `json:"observation"`
	}
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&page); err != nil {
		t.Fatal(err)
	}
	s := page.Observation
	if code != 200 || page.SchemaVersion != 1 || s == nil || s.Epoch != epoch || s.At == 0 || s.Active != 0 || s.lifecycleCounters != (lifecycleCounters{8, 8, 2, 1}) {
		t.Fatal(body)
	}
	worker.stop()
	code, body = remoteGet(path, token, "127.0.0.1")
	if code != 200 || strings.TrimSpace(body) != `{"schemaVersion":1,"observation":null}` {
		t.Fatal(body)
	}
}
