package main

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const repositoryFeed = "https://raw.githubusercontent.com/Fogiku/VpnGuard_linux/releases/"
const repositoryReceipt = "/run/vpnguard-repository-update.json"

var releaseNumber = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})(\.(0|[1-9][0-9]{0,5}))?$`)
var releaseJob = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}-[0-9]{6}$`)

//go:embed deploy/guarded_update.py
var updateGuard []byte

//go:embed deploy/repository_install.py
var repositoryInstaller []byte

type repositoryRelease struct {
	Version string            `json:"version"`
	SHA256  map[string]string `json:"sha256"`
}

func releaseParts(s string) [3]int {
	var n [3]int
	for i, part := range strings.Split(s, ".") {
		n[i], _ = strconv.Atoi(part)
	}
	return n
}

func newerRelease(candidate, installed string) bool {
	if !releaseNumber.MatchString(candidate) || !releaseNumber.MatchString(installed) {
		return false
	}
	a, b := releaseParts(candidate), releaseParts(installed)
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

func fetchRelease() (repositoryRelease, error) {
	var release repositoryRelease
	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Get(repositoryFeed + "manifest.json")
	if err != nil {
		return release, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return release, fmt.Errorf("репозиторий вернул HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8193))
	if err != nil {
		return release, err
	}
	if len(body) > 8192 || json.Unmarshal(body, &release) != nil || !releaseNumber.MatchString(release.Version) {
		return release, errors.New("некорректный манифест выпуска")
	}
	hash, err := hex.DecodeString(release.SHA256[runtime.GOARCH])
	if err != nil || len(hash) != 32 {
		return release, fmt.Errorf("нет контрольной суммы для %s", runtime.GOARCH)
	}
	return release, nil
}

type installReceipt struct {
	Status    string `json:"status"`
	Version   string `json:"version"`
	Requester string `json:"requester"`
	Job       string `json:"job"`
	Message   string `json:"message"`
}

func readInstallReceipt() (installReceipt, error) {
	var r installReceipt
	data, err := os.ReadFile(repositoryReceipt)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(data, &r); err != nil {
		return r, err
	}
	if r.Job != "" {
		if !releaseJob.MatchString(r.Job) {
			return r, errors.New("некорректный идентификатор установки")
		}
		var job struct{ Status string }
		data, err = os.ReadFile(filepath.Join("/var/backups/vpnguard/updates", r.Job, "job.json"))
		if err != nil {
			return r, err
		}
		if err = json.Unmarshal(data, &job); err != nil {
			return r, err
		}
		r.Status = job.Status
	}
	return r, nil
}

func startRepositoryUpdate(version, requester string) error {
	if Sim || runtime.GOOS != "linux" || DataDir != "/var/lib/vpnguard" {
		return errors.New("установка доступна на штатном Linux-шлюзе")
	}
	r, err := fetchRelease()
	if err != nil {
		return err
	}
	if version != r.Version || !newerRelease(version, Version) {
		return errors.New("список версий изменился или обновление уже установлено")
	}
	receipt, err := readInstallReceipt()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if receipt.Status == "installed" || receipt.Status == "prepared" || receipt.Status == "rollback_failed" {
		return errors.New("предыдущее обновление ещё не завершено")
	}
	dir, err := os.MkdirTemp("/run", "vpnguard-release-")
	if err != nil {
		return err
	}
	for name, content := range map[string][]byte{"repository_install.py": repositoryInstaller, "guarded_update.py": updateGuard, "route_guard.py": routeGuardSource} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0600); err != nil {
			os.RemoveAll(dir)
			return err
		}
	}
	// The transient service survives replacement/restart of the web agent and cleans its staging files.
	out, err := exec.Command("systemd-run", "--collect", "--unit=vpnguard-repository-update", "/usr/bin/python3", "-I", filepath.Join(dir, "repository_install.py"), strings.TrimSuffix(repositoryFeed, "releases/")+"bin-v"+version+"/", version, runtime.GOARCH, r.SHA256[runtime.GOARCH], requester).CombinedOutput()
	if err != nil {
		os.RemoveAll(dir)
		return fmt.Errorf("запуск обновления: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func confirmRepositoryUpdate(jobID, requester string) error {
	if Sim || runtime.GOOS != "linux" || DataDir != "/var/lib/vpnguard" {
		return errors.New("подтверждение доступно только на шлюзе")
	}
	r, err := readInstallReceipt()
	if err != nil {
		return err
	}
	if !releaseJob.MatchString(jobID) || r.Job != jobID || r.Requester != requester || r.Version != Version || r.Status != "installed" {
		return errors.New("нет ожидающего обновления для этого клиента и версии")
	}
	job := filepath.Join("/var/backups/vpnguard/updates", jobID)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/python3", "-I", filepath.Join(job, "guard.py"), "confirm", job).CombinedOutput()
	if err != nil {
		return fmt.Errorf("проверка шлюза: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
