package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type zapretProposal struct {
	Status string   `json:"status"`
	Steps  []string `json:"steps"`
	Reason string   `json:"reason"`
}
type draftTrial struct {
	Finished string `json:"finished"`
	Outcome  string `json:"outcome"`
	Detail   string `json:"detail"`
}

type zapretDraft struct {
	FlowSamples []discordSample `json:"flowSamples,omitempty"`
	Trial       *draftTrial     `json:"trial,omitempty"`
	zapretProposal
	Base       string `json:"base,omitempty"`
	Scenario   string `json:"scenario,omitempty"`
	Model      string `json:"model,omitempty"`
	Created    string `json:"created,omitempty"`
	BaseSHA256 string `json:"baseSha256,omitempty"`
	Original   string `json:"original"`
	Args       string `json:"args,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
}

const latestDraftFile = "zapret-draft.json"

func readLatestDraft() (zapretDraft, error) {
	var draft zapretDraft
	data, err := os.ReadFile(filepath.Join(DataDir, latestDraftFile))
	if errors.Is(err, os.ErrNotExist) {
		return draft, errors.New("Сохранённого черновика пока нет")
	}
	if err != nil {
		return draft, err
	}
	if err := json.Unmarshal(data, &draft); err != nil {
		return draft, errors.New("Не удалось прочитать сохранённый черновик")
	}
	args, err := compileDraftSteps(draft.Steps)
	if err != nil || draft.Status != "draft" || draft.Args != args || draft.SHA256 != draftHash(args) {
		return zapretDraft{}, errors.New("Содержимое черновика не соответствует сохранённой ревизии")
	}
	draft.BaseSHA256 = draftHash(draft.Original)
	return draft, nil
}

func testSavedDraft(revision string) (draftTrial, error) {
	var trial draftTrial
	if !draftRequest.TryLock() {
		return trial, errors.New("черновик занят, повторите проверку позже")
	}
	defer draftRequest.Unlock()
	draft, err := readLatestDraft()
	if err != nil {
		return trial, err
	}
	if revision != draft.SHA256 {
		return trial, errors.New("черновик изменился, откройте последнюю ревизию")
	}
	message, err := trialZapretArgs("ИИ-черновик", draft.Args, "http")
	if errors.Is(err, errZapretTrialBusy) {
		return trial, err
	}
	trial.Finished = time.Now().UTC().Format(time.RFC3339)
	switch {
	case err != nil:
		trial.Outcome = "failed"
		detail := []rune(err.Error())
		if len(detail) > 1024 {
			detail = append(detail[:1024], '…')
		}
		trial.Detail = string(detail)
	case Sim:
		trial.Outcome = "simulated"
		trial.Detail = message
	default:
		trial.Outcome = "passed"
		trial.Detail = message
	}
	draft.Trial = &trial
	if err := saveJSON(latestDraftFile, draft); err != nil {
		return trial, fmt.Errorf("не удалось сохранить результат проверки: %w", err)
	}
	return trial, nil
}

func draftHash(args string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(args+"\n")))
}

func compileDraftSteps(steps []string) (string, error) {
	if len(steps) == 0 || len(steps) > len(zapretStepArgs) {
		return "", errors.New("неверное число шагов профиля")
	}
	args := []string{zapretBaseArgs}
	seen := map[string]bool{}
	for _, step := range steps {
		arg, ok := zapretStepArgs[step]
		if !ok || seen[step] {
			return "", errors.New("неизвестный или повторный шаг профиля")
		}
		seen[step] = true
		args = append(args, arg)
	}
	return strings.Join(args, " "), nil
}

var draftRequest sync.Mutex

func generateZapretDraft(base, scenario, symptom, model, endpoint string, samples ...discordSample) (zapretDraft, error) {
	var draft zapretDraft
	for _, p := range draftBaselines() {
		if p.Name == base {
			draft.Original = p.Args
			break
		}
	}
	if draft.Original == "" || (scenario != "youtube" && scenario != "discord") || (symptom != "unknown" && symptom != "failed" && symptom != "intermittent" && symptom != "tcp_without_observed_reply") {
		return draft, errors.New("проверьте исходный профиль, сценарий и наблюдение")
	}
	if symptom == "unknown" {
		draft.Status = "need_data"
		draft.Reason = "Проверьте выбранное приложение и независимый HTTPS-сайт на одном устройстве."
		return draft, nil
	}
	model = strings.TrimSpace(model)
	if model == "" {
		return draft, errors.New("выберите «Настроить локальный ИИ» и дождитесь загрузки модели")
	}
	if strings.HasSuffix(strings.ToLower(model), ":cloud") || strings.HasSuffix(strings.ToLower(model), "-cloud") {
		return draft, errors.New("выберите локально установленную модель Ollama")
	}
	if !draftRequest.TryLock() {
		return draft, errors.New("черновик занят, повторите генерацию позже")
	}
	defer draftRequest.Unlock()
	context := map[string]any{"baseline": base, "scenario": scenario, "device_observation": symptom, "diagnostics": readDiagnosticSnapshotV1()}
	if counts := flowsMod.unansweredByApp(); len(counts) > 0 {
		context["zapret_tcp_without_observed_reply_two_snapshots"] = counts
	}
	context["services_to_preserve"] = []string{"youtube", "discord_gateway"}
	if len(samples) > 0 {
		context["client_tcp_observations"] = samples
		draft.FlowSamples = samples
	}
	input, _ := json.Marshal(context)
	const instruction = `Предложи один экспериментальный профиль для указанной проблемы. Верни JSON с полями status, steps и reason. Для status=draft составь новый упорядоченный список из шагов fake, multisplit, multidisorder, hostfakesplit, без повторов. Запрещено копировать готовые списки [fake], [fake,multisplit], [multidisorder], [hostfakesplit]. В reason кратко по-русски опиши гипотезу и что измерить на устройстве. Это гипотеза без измерения эффективности. Если данных мало, верни status=need_data, пустой steps и укажи недостающий замер.`
	payload, _ := json.Marshal(map[string]any{"model": model, "stream": false, "format": "json", "keep_alive": "0s", "options": map[string]int{"num_ctx": 2048, "num_predict": 384, "num_thread": 2}, "messages": []map[string]string{{"role": "system", "content": instruction}, {"role": "user", "content": string(input)}}})
	client := http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(payload))
	if err != nil {
		return draft, errors.New("локальный Ollama недоступен или истекло время ожидания")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return draft, fmt.Errorf("Ollama вернул HTTP %d; проверьте имя и наличие модели", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16385))
	var envelope struct {
		Done    bool
		Message struct{ Content string }
	}
	if err != nil || len(raw) > 16384 || json.Unmarshal(raw, &envelope) != nil || !envelope.Done || json.Unmarshal([]byte(envelope.Message.Content), &draft.zapretProposal) != nil {
		return draft, errors.New("модель вернула неполный или некорректный JSON")
	}
	draft.Reason = strings.TrimSpace(draft.Reason)
	if draft.Reason == "" || len(draft.Reason) > 2048 {
		return draft, errors.New("модель не дала краткого обоснования")
	}
	if draft.Status == "need_data" && len(draft.Steps) == 0 {
		return draft, nil
	}
	if draft.Status != "draft" {
		return draft, errors.New("неверный статус черновика")
	}
	args, err := compileDraftSteps(draft.Steps)
	if err != nil {
		return draft, err
	}
	for _, p := range draftBaselines() {
		if p.Args == args {
			return draft, errors.New("модель повторила встроенный профиль; новый черновик не создан")
		}
	}
	draft.Args = args
	draft.SHA256 = draftHash(args)
	draft.BaseSHA256 = draftHash(draft.Original)
	draft.Base, draft.Model, draft.Scenario = base, model, scenario
	draft.Created = time.Now().UTC().Format(time.RFC3339)
	if err := saveJSON(latestDraftFile, draft); err != nil {
		return draft, fmt.Errorf("не удалось сохранить черновик: %w", err)
	}
	return draft, nil
}
