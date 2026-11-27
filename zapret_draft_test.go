package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestZapretDraftProvider(t *testing.T) {
	setup(t)
	var proposal zapretProposal
	calls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var request struct {
			Model, Format string
			Stream        bool
			Messages      []struct{ Role, Content string }
		}
		if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&request) != nil || request.Model != "lab" || request.Format != "json" || request.Stream || len(request.Messages) != 2 || !strings.Contains(request.Messages[1].Content, "device_observation") {
			t.Error("unexpected Ollama request")
		}
		content, err := json.Marshal(proposal)
		if err != nil {
			t.Error(err)
		}
		json.NewEncoder(w).Encode(map[string]any{"done": true, "message": map[string]string{"content": string(content)}})
	}))
	defer provider.Close()
	gen := func() (zapretDraft, error) {
		return generateZapretDraft("fake", "youtube", "failed", "lab", provider.URL)
	}
	proposal = zapretProposal{"draft", []string{"multisplit"}, "Сравните воспроизведение одного ролика."}
	draft, err := gen()
	if err != nil || draft.Args == draft.Original || !strings.HasSuffix(draft.Args, zapretStepArgs["multisplit"]) || draft.SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(draft.Args+"\n"))) {
		t.Fatal(draft, err)
	}
	revision := draft.SHA256
	for _, steps := range [][]string{nil, {"--lua-init=@/tmp/script"}, {"fake", "fake"}, {"fake"}, {"fake", "multisplit"}} {
		proposal.Steps = steps
		if _, err = gen(); err == nil {
			t.Fatal("accepted steps", steps)
		}
	}
	proposal = zapretProposal{"need_data", nil, "Нужен клиентский замер."}
	if draft, err = gen(); err != nil || draft.Status != "need_data" || draft.Args != "" {
		t.Fatal(draft, err)
	}
	before := calls
	if draft, err = generateZapretDraft("fake", "discord", "unknown", "lab", provider.URL); err != nil || draft.Status != "need_data" || before != calls {
		t.Fatal(draft, err)
	}
	saved, err := readLatestDraft()
	if err != nil || saved.SHA256 != revision || saved.Base != "fake" || saved.Model != "lab" || saved.Scenario != "youtube" || saved.Created == "" {
		t.Fatalf("latest draft after failed proposals: %+v, %v", saved, err)
	}
	if _, err := testSavedDraft("obsolete"); err == nil {
		t.Fatal("accepted stale revision")
	}
	trial, err := testSavedDraft(revision)
	if err != nil || trial.Outcome != "simulated" || trial.Finished == "" {
		t.Fatal(trial, err)
	}
	saved, err = readLatestDraft()
	if err != nil || saved.Trial == nil || *saved.Trial != trial {
		t.Fatal(saved.Trial, err)
	}
	saved.Args += " corrupted"
	if err := saveJSON(latestDraftFile, saved); err != nil {
		t.Fatal(err)
	}
	if _, err := readLatestDraft(); err == nil {
		t.Fatal("accepted corrupt revision")
	}
}

type draftTrialSys struct {
	Sys
	output string
	code   int
}

func (sys draftTrialSys) Run(_ time.Duration, _, name string, args ...string) (string, int) {
	if name != "unshare" {
		return "unexpected command", 1
	}
	return sys.output, sys.code
}

func TestSavedDraftTrialOutcomes(t *testing.T) {
	sim := setup(t)
	args, err := compileDraftSteps([]string{"multisplit"})
	if err != nil {
		t.Fatal(err)
	}
	draft := zapretDraft{zapretProposal: zapretProposal{Status: "draft", Steps: []string{"multisplit"}}, Args: args, SHA256: draftHash(args)}
	if err := saveJSON(latestDraftFile, draft); err != nil {
		t.Fatal(err)
	}
	Sim = false
	defer func() { Sim = true; S = sim }()
	for _, tc := range []struct {
		output  string
		code    int
		outcome string
	}{
		{"http 7", 0, "passed"}, {"http 0", 0, "failed"}, {"unavailable", 1, "failed"},
	} {
		S = draftTrialSys{sim, tc.output, tc.code}
		trial, err := testSavedDraft(draft.SHA256)
		if err != nil || trial.Outcome != tc.outcome {
			t.Fatal(trial, err)
		}
		stored, err := readLatestDraft()
		if err != nil || stored.Trial == nil || *stored.Trial != trial {
			t.Fatal(stored.Trial, err)
		}
	}
}

func TestZapretGeneratedLinux(t *testing.T) {
	// Reuse the disposable network trial and its real nfqws2 acceptance harness.
	if os.Getenv("VPNGUARD_TEST_NFQWS2_TRIAL") != "1" {
		t.Skip("requires disposable Linux namespace and installed zapret2")
	}
	oldSys, oldSim := S, Sim
	S, Sim = realSys{}, false
	defer func() { S, Sim = oldSys, oldSim }()
	args, err := compileDraftSteps([]string{"multisplit"})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := trialZapretArgs("Черновик", args, "http")
	if err != nil || !strings.Contains(msg, "оба контрольных HTTP-ответа") {
		t.Fatal(msg, err)
	}
	t.Log(msg)
}
