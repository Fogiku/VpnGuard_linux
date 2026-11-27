package main

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed deploy/local_ai_setup.py
var aiSetupScript string

var localModels = []Opt{{"qwen2.5:1.5b", "Qwen 2.5 1.5B · для N200"}, {"qwen2.5:3b", "Qwen 2.5 3B"}, {"qwen2.5:7b", "Qwen 2.5 7B"}}

var aiSetup struct {
	sync.Mutex
	running bool
	status  string
}

func aiModel() string {
	return cfg("zapret.aiModel", strings.TrimSpace(os.Getenv("VPNGUARD_ZAPRET_MODEL")))
}

func aiSetupTable() Table {
	aiSetup.Lock()
	defer aiSetup.Unlock()
	model := aiModel()
	if model == "" {
		model = "не выбрана"
	}
	state := aiSetup.status
	if state == "" {
		state = "Ожидание"
	}
	return Table{Title: "Локальный ИИ", Cols: []string{"Выбранная модель", "Настройка"}, Rows: [][]string{{model, state}}}
}

func setupLocalAI(model string) (string, error) {
	allowed := false
	for _, opt := range localModels {
		if model == opt.V {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", errors.New("выберите модель из списка")
	}
	if Sim {
		return "Симулятор: установка Ollama и загрузка модели доступны на шлюзе Linux.", nil
	}
	aiSetup.Lock()
	if aiSetup.running {
		aiSetup.Unlock()
		return "", errors.New("настройка локального ИИ уже выполняется")
	}
	aiSetup.running, aiSetup.status = true, "Проверка Ollama"
	aiSetup.Unlock()
	go func() {
		msg, err := prepareLocalAI(S, model, func(s string) { aiSetup.Lock(); aiSetup.status = s; aiSetup.Unlock() })
		aiSetup.Lock()
		defer aiSetup.Unlock()
		aiSetup.running = false
		aiSetup.status = msg
		if err != nil {
			aiSetup.status = err.Error()
		}
	}()
	return "Начата настройка. Состояние отображается в таблице «Локальный ИИ».", nil
}

func prepareLocalAI(sys Sys, model string, progress func(string)) (string, error) {
	last := ""
	code := sys.Stream(90*time.Minute, aiSetupScript, func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && s != last {
			last = s
			progress(s)
		}
	}, "python3", "-I", "-u", "-", model)
	if code != 0 {
		return "", fmt.Errorf("Настройка прервана (код %d). %s", code, last)
	}
	if err := setCfg("zapret.aiModel", model); err != nil {
		return "", err
	}
	return "Готово: " + model, nil
}
