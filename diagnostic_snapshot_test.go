package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticSnapshotV1(t *testing.T) {
	oldDir, oldCfg, oldMods := DataDir, cfgMap, Mods
	oldDecisions := snapshotLog(&decRing)
	t.Cleanup(func() {
		DataDir, cfgMap, Mods = oldDir, oldCfg, oldMods
		logMu.Lock()
		decRing = oldDecisions
		logMu.Unlock()
	})
	DataDir = t.TempDir()
	const secret = "private-client-fixture"
	cfgMap = map[string]string{"remote.enabled": "true", "remote.token": secret,
		"remote.until": time.Now().Add(time.Hour).Format(time.RFC3339)}
	known := &flowTestExit{id: "wg"}
	known.setSt(1, true, secret, secret, [2]string{secret, secret})
	Mods = []Module{known, &flowTestExit{id: secret}}
	logMu.Lock()
	decRing = []LogLine{{Lvl: "WARN", Text: secret}, {Lvl: secret, Text: secret}}
	logMu.Unlock()
	const path = "/v1/diagnostics/snapshot"
	code, body := remoteGet(path, secret, "127.0.0.1")
	if code != 200 || strings.Contains(body, secret) || len(body) > 2048 {
		t.Fatal("invalid or unfiltered snapshot")
	}
	var s diagnosticSnapshotV1
	d := json.NewDecoder(strings.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != 1 || s.AgentVersion != Version || len(s.Modules) != 1 ||
		s.Modules[0] != (diagnosticModuleV1{"wg", 1, true}) ||
		s.Decisions != (diagnosticDecisionsV1{Warning: 1, Other: 1}) {
		t.Fatal("unexpected snapshot contents")
	}
	if code, _ := remoteGet(path, "", "127.0.0.1"); code != http.StatusUnauthorized {
		t.Fatal("missing token accepted")
	}
	if code, _ := remoteGet(path, secret, "203.0.113.2"); code != http.StatusForbidden {
		t.Fatal("address restriction ignored")
	}
	req, _ := http.NewRequest(http.MethodPost, path, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Token", secret)
	w := &recorder{}
	remoteServe(w, req)
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET" {
		t.Fatal("unexpected method policy")
	}
}
