package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const ndpiInstallAction = "install-ndpi"

func (m *flowModule) Actions() []Action {
	return []Action{{ID: ndpiInstallAction, Title: "Установить libndpi-bin", Danger: true,
		Confirm: "Установить libndpi-bin из настроенных APT-репозиториев шлюза и проверить ndpiReader 4.2.0?"}}
}

func (m *flowModule) Do(id string, _ map[string]string) (string, error) {
	if id != ndpiInstallAction {
		return "", errors.New("неизвестное действие модуля потоков")
	}
	if !m.installMu.TryLock() {
		return "", errors.New("установка libndpi-bin уже выполняется")
	}
	defer m.installMu.Unlock()
	m.busy("проверка и установка libndpi-bin")
	defer m.busy("")
	msg := "Имитация: установка пакета доступна на шлюзе Linux."
	var err error
	if !Sim {
		msg, err = installNDPI(S)
	}
	m.mu.Lock()
	if err != nil {
		m.installStatus = err.Error()
	} else {
		m.installStatus = msg
	}
	m.mu.Unlock()
	return msg, err
}

// The Ubuntu 4.2 reader prints its extcap version and help, then exits with status 1.
func hasNDPI42(sys Sys) bool {
	out, code := sys.Run(5*time.Second, "", "ndpiReader", "--extcap-version")
	return (code == 0 || code == 1) && strings.Contains("\n"+out+"\n", "\nextcap {version=4.2.0}\n")
}

var ndpiPackageVersion = regexp.MustCompile(`^([0-9]+:)?4\.2(\.0)?-[0-9A-Za-z.+~]+$`)

func ndpiCandidate(sys Sys) string {
	out, code := sys.Run(10*time.Second, "", "env", "LC_ALL=C", "apt-cache", "policy", "libndpi-bin")
	if code == 0 {
		for _, line := range strings.Split(out, "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Candidate:"); ok {
				if v = strings.TrimSpace(v); v != "(none)" {
					return v
				}
			}
		}
	}
	return ""
}

func installNDPI(sys Sys) (string, error) {
	if hasNDPI42(sys) {
		return "ndpiReader 4.2.0 уже установлен и готов к работе.", nil
	}
	candidate := ndpiCandidate(sys)
	if candidate == "" {
		_, code := sys.Run(3*time.Minute, "", "env", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", "Acquire::Retries=1", "update")
		if code != 0 {
			return "", errors.New("APT не обновил список пакетов. Проверьте доступность репозиториев и занятость APT.")
		}
		candidate = ndpiCandidate(sys)
	}
	if candidate == "" {
		return "", errors.New("APT не нашёл libndpi-bin. На Ubuntu 24.04 проверьте репозиторий Universe.")
	}
	if !ndpiPackageVersion.MatchString(candidate) {
		return "", fmt.Errorf("версия libndpi-bin в APT (%s) несовместима. Требуется ndpiReader 4.2.0.", candidate)
	}
	_, code := sys.Run(5*time.Minute, "", "env", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive",
		"apt-get", "-o", "DPkg::Lock::Timeout=30", "install", "-y", "--no-install-recommends", "--no-remove", "libndpi-bin="+candidate)
	if code != 0 {
		return "", errors.New("APT не установил libndpi-bin. Проверьте журнал APT, доступность репозитория и занятость менеджера пакетов.")
	}
	if !hasNDPI42(sys) {
		return "", errors.New("APT завершил установку, но команда ndpiReader не подтвердила версию 4.2.0.")
	}
	return "Установлен libndpi-bin. Проверена версия ndpiReader 4.2.0.", nil
}
