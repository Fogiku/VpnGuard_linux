package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMeduzaLocationChoices(t *testing.T) {
	var response map[string]any
	err := json.Unmarshal([]byte(`{"data":[{"id":"9","names":[{"lang":"en_us","name":"Netherlands"},{"lang":"ru_ru","name":"Нидерланды"}],"packages":[{"id":"14","city_id":"amsterdam","city_names":[{"lang":"ru_ru","name":"Амстердам"}],"pricing":[{}],"ru_warning":true},{"id":"59","city_id":"amsterdam","pricing":[{}]},{"id":"60","city_id":"hidden","pricing":[]}]},{"id":"23","recommended":true,"names":[{"lang":"ru_ru","name":"Канада"}],"packages":[{"names":[{"lang":"en_us","name":"Toronto-2"}],"pricing":[{}]}]}]}`), &response)
	if err != nil {
		t.Fatal(err)
	}
	choices := parseMeduzaLocations(response["data"])
	if len(choices) != 2 {
		t.Fatalf("city deduplication/filtering: %+v", choices)
	}
	if choices[0].Key != "23:toronto" || choices[0].Group != "23" || choices[0].City != "toronto" {
		t.Fatalf("API parameters: %+v", choices[0])
	}
	if choices[1].Label != "Нидерланды — Амстердам" || choices[1].Warning {
		t.Fatalf("localized city or warning: %+v", choices[1])
	}
}

func TestMeduzaLocationAPIRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer test-only-token" {
			t.Error("missing server-side authentication")
		}
		if r.Method != http.MethodPost || r.URL.Path != "/services/10008620/change-location" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if payload["group_id"] != "23" || payload["city_id"] != "toronto" {
			t.Errorf("invalid payload: %v", payload)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","data":{"queued":true}}`))
	}))
	defer server.Close()
	_, status, err := meduzaAccountRequest(server.Client(), "test-only-token", http.MethodPost, server.URL+"/services/10008620/change-location", map[string]string{"group_id": "23", "city_id": "toronto"})
	if err != nil || status != 200 || requests != 1 {
		t.Fatalf("request result %d, %v, count %d", status, err, requests)
	}
}
func TestMeduzaLocationAPIFailureDoesNotRetry(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(409)
		w.Write([]byte(`{"status":"error","message":"operation already running"}`))
	}))
	defer server.Close()
	_, _, err := meduzaAccountRequest(server.Client(), "secret-token", http.MethodPost, server.URL, nil)
	if err == nil || requests != 1 || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("unsafe failure: %v (%d requests)", err, requests)
	}
}
func TestMeduzaLocationValidationBeforeChange(t *testing.T) {
	setup(t)
	setCfg("meduza.serviceId", "10008620")
	m := &meduza{services: []mdzItem{{ID: "10008620"}}}
	if _, err := m.changeLocation(map[string]string{"service": "other"}); err == nil {
		t.Fatal("stale service accepted")
	}
	m.lmu.Lock()
	m.locationUntil = time.Now().Add(time.Minute)
	m.lmu.Unlock()
}
