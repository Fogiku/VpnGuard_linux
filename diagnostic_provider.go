package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type providerAdvice struct {
	Recommendation string `json:"recommendation"`
	Confidence     string `json:"confidence"`
}

type diagnosticReview struct {
	Local  diagnosticExplanationV1 `json:"local"`
	Advice *providerAdvice         `json:"advice,omitempty"`
	Status string                  `json:"status"`
}

const providerEnv = "VPNGUARD_DIAGNOSTIC_PROVIDER"

var providerRequest sync.Mutex
var providerHTTP = &http.Client{
	Timeout: 8 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func reviewDiagnostics(snapshot diagnosticSnapshotV1, endpoint string, client *http.Client) diagnosticReview {
	result := diagnosticReview{Local: explainDiagnosticSnapshot(snapshot), Status: "disabled"}
	if endpoint == "" {
		return result
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || !net.ParseIP(u.Hostname()).IsLoopback() || u.User != nil || u.Fragment != "" {
		result.Status = "invalid_endpoint"
		return result
	}
	if !providerRequest.TryLock() {
		result.Status = "busy"
		return result
	}
	defer providerRequest.Unlock()
	result.Status = "unavailable"
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return result
	}
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(payload))
	if err != nil {
		return result
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return result
	}
	const limit = 8192
	result.Status = "invalid_response"
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	var advice providerAdvice
	if err != nil || len(raw) > limit || json.Unmarshal(raw, &advice) != nil {
		return result
	}
	advice.Recommendation = strings.TrimSpace(advice.Recommendation)
	if advice.Recommendation == "" || len(advice.Recommendation) > 4096 {
		return result
	}
	switch advice.Confidence {
	case "low", "medium", "high":
		result.Status, result.Advice = "ok", &advice
	}
	return result
}

func configuredDiagnosticProvider() string {
	return strings.TrimSpace(os.Getenv(providerEnv))
}
