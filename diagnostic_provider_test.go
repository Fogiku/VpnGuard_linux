package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticProvider(t *testing.T) {
	snapshot := diagnosticSnapshotV1{SchemaVersion: 1, RoutingReady: true, Modules: []diagnosticModuleV1{{"dns", 1, false}}}
	for _, tc := range []struct{ name, body, status string }{
		{"ok", `{"recommendation":"Проверить DNS","confidence":"medium"}`, "ok"},
		{"missing confidence", `{"recommendation":"x"}`, "invalid_response"},
		{"empty", `{"recommendation":" ","confidence":"low"}`, "invalid_response"},
		{"oversized", strings.Repeat(" ", 8200), "invalid_response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var got diagnosticSnapshotV1
				if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&got) != nil || len(got.Modules) != 1 || got.Modules[0] != snapshot.Modules[0] {
					t.Error("unexpected provider request")
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			result := reviewDiagnostics(snapshot, srv.URL, providerHTTP)
			if result.Status != tc.status || (result.Advice != nil) != (tc.status == "ok") || len(result.Local.Observations) == 0 {
				t.Fatalf("unexpected review: %+v", result)
			}
		})
	}
	for endpoint, status := range map[string]string{"": "disabled", "http://192.0.2.1/model": "invalid_endpoint"} {
		if result := reviewDiagnostics(snapshot, endpoint, providerHTTP); result.Status != status || result.Local.Summary == "" {
			t.Fatal("missing fallback", status)
		}
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(200 * time.Millisecond) }))
	defer slow.Close()
	client := &http.Client{Timeout: 100 * time.Millisecond}
	if result := reviewDiagnostics(snapshot, slow.URL, client); result.Status != "unavailable" || result.Local.Summary == "" {
		t.Fatal("missing timeout fallback")
	}
}
