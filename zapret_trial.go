package main

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed deploy/zapret_trial.py
var zapretTrialWorker string
var zapretTrialMu sync.Mutex
var errZapretTrialBusy = errors.New("испытательный запуск уже выполняется")

func trialZapretPreset(name, mode string) (string, error) {
	var args string
	for _, p := range builtinZapretStrategies() {
		if p.Name == name {
			args = p.Args
			break
		}
	}
	if args == "" {
		return "", errors.New("выберите встроенный профиль")
	}
	return trialZapretArgs(name, args, mode)
}

func trialZapretArgs(name, args, mode string) (string, error) {
	if mode == "" {
		mode = "startup"
	}
	if mode != "startup" && mode != "http" {
		return "", errors.New("неизвестный режим испытания")
	}
	revision := fmt.Sprintf("%x", sha256.Sum256([]byte(args+"\n")))
	if Sim {
		return fmt.Sprintf("Симулятор: профиль «%s», SHA-256 %s. Запуск доступен на шлюзе Linux.", name, revision), nil
	}
	if !zapretTrialMu.TryLock() {
		return "", errZapretTrialBusy
	}
	defer zapretTrialMu.Unlock()
	parent, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return "", err
	}
	// A PID namespace with a kill-on-parent-exit supervisor bounds the daemon lifetime.
	cmd := []string{"--net", "--pid", "--fork", "--kill-child=KILL", "--mount-proc", "--", "python3", "-I", "-c", zapretTrialWorker, parent, mode}
	cmd = append(cmd, strings.Fields(args)...)
	out, code := S.Run(18*time.Second, "", "unshare", cmd...)
	out = strings.TrimSpace(out)
	if code != 0 {
		return "", fmt.Errorf("испытательный запуск nfqws2: %s", out)
	}
	if mode == "http" {
		value, ok := strings.CutPrefix(out, "http ")
		count, err := strconv.ParseUint(value, 10, 32)
		if !ok || err != nil || count == 0 {
			return "", errors.New("некорректный результат проверки очереди")
		}
		return fmt.Sprintf("Профиль «%s»: оба контрольных HTTP-ответа получены. Через NFQUEUE 200 прошло пакетов: %d. SHA-256 %s", name, count, revision), nil
	}
	if out != "ready" {
		return "", errors.New("процесс не подтвердил готовность")
	}
	return fmt.Sprintf("Профиль «%s»: nfqws2 занял NFQUEUE 200 в испытательной сети и завершён. SHA-256 %s", name, revision), nil
}
