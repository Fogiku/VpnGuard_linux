package main

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed deploy/zapret_trial.py
var zapretTrialWorker string
var zapretTrialMu sync.Mutex

func trialZapretPreset(name string) (string, error) {
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
	revision := fmt.Sprintf("%x", sha256.Sum256([]byte(args+"\n")))
	if Sim {
		return fmt.Sprintf("Симулятор: профиль «%s», SHA-256 %s. Запуск доступен на шлюзе Linux.", name, revision), nil
	}
	if !zapretTrialMu.TryLock() {
		return "", errors.New("испытательный запуск уже выполняется")
	}
	defer zapretTrialMu.Unlock()
	parent, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return "", err
	}
	// A PID namespace with a kill-on-parent-exit supervisor bounds the daemon lifetime.
	cmd := []string{"--net", "--pid", "--fork", "--kill-child=KILL", "--mount-proc", "--", "python3", "-I", "-c", zapretTrialWorker, parent}
	cmd = append(cmd, strings.Fields(args)...)
	out, code := S.Run(12*time.Second, "", "unshare", cmd...)
	if code != 0 || strings.TrimSpace(out) != "ready" {
		return "", fmt.Errorf("испытательный запуск nfqws2: %s", strings.TrimSpace(out))
	}
	return fmt.Sprintf("Профиль «%s»: nfqws2 занял NFQUEUE 200 в испытательной сети и завершён. SHA-256 %s", name, revision), nil
}
