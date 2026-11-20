package main

import (
	"context"
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
	if _, ok := worker.status(); ok {
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
		if _, ok := s.status(); ok {
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
	if _, ok := s.status(); ok {
		t.Fatal("cancel retained continuity")
	}
	s = startFlowEvents(eventTestRunner{line: `{"epoch":"bad","rows":[]}`})
	select {
	case <-s.done:
	case <-time.After(time.Second):
		t.Fatal("invalid frame not rejected")
	}
	if _, ok := s.status(); ok {
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
	if _, ok := s.status(); ok {
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
	if _, ok := s.status(); !ok {
		t.Fatal("real heartbeat stopped")
	}
	s.stop()
	if _, ok := s.status(); ok {
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
