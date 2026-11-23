package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed deploy/vpnguard-olcrtc-peer@.service
var olcPeerUnit string

//go:embed deploy/install-olcrtc.sh
var olcInstaller string

var olcInstallMu sync.Mutex

func ensureOlcInstalled() error {
	olcInstallMu.Lock()
	defer olcInstallMu.Unlock()
	if olcInstalled() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-eu")
	cmd.Stdin = strings.NewReader(olcInstaller)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("установка olcRTC: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

const olcTemplate = "/etc/systemd/system/vpnguard-olcrtc-peer@.service"
const olcBinary = "/usr/local/bin/olcrtc"

var olcRoomPath = regexp.MustCompile("^/[A-Za-z0-9_-]+$")
var olcPeerID = regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$")

type olcServer struct {
	base
	rows [][]string
}

var inboundOlc = &olcServer{}

func init()                      { Register(inboundOlc) }
func (*olcServer) ID() string    { return "olcrtc-server" }
func (*olcServer) Name() string  { return "olcRTC-Server" }
func (*olcServer) Order() int    { return 6 }
func (*olcServer) Color() string { return "#68a8d6" }
func olcDir() string {
	if Sim {
		return filepath.Join(DataDir, "olcrtc-peers")
	}
	return "/etc/vpnguard/olcrtc-peers"
}
func olcInstalled() bool {
	if Sim {
		return true
	}
	st, err := os.Stat(olcBinary)
	return err == nil && st.Mode().IsRegular() && st.Mode()&0111 != 0
}
func olcUnit(name string) string { return "vpnguard-olcrtc-peer@" + name + ".service" }

type olcSocks struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type olcConfig struct {
	Mode string `json:"mode"`
	Auth struct {
		Provider string `json:"provider"`
	} `json:"auth"`
	Room struct {
		ID string `json:"id"`
	} `json:"room"`
	Crypto struct {
		Key string `json:"key"`
	} `json:"crypto"`
	Net struct {
		Transport string `json:"transport"`
		DNS       string `json:"dns"`
	} `json:"net"`
	Socks *olcSocks `json:"socks,omitempty"`
}

func readOlcPeer(name string) (olcConfig, error) {
	var c olcConfig
	if !olcPeerID.MatchString(name) {
		return c, errors.New("недопустимое имя клиента")
	}
	b, err := os.ReadFile(filepath.Join(olcDir(), name+".yaml"))
	if err != nil {
		return c, err
	}
	if json.Unmarshal(b, &c) != nil || c.Mode != "srv" || len(c.Crypto.Key) != 64 {
		return c, errors.New("повреждена конфигурация клиента")
	}
	return c, nil
}

func olcRoomID(provider, room string) (string, error) {
	switch provider {
	case "telemost", "wbstream":
		if provider == "telemost" {
			room = strings.TrimPrefix(room, "https://telemost.yandex.ru/j/")
		}
		if len(room) > 512 || room == "any" || !olcRoomPath.MatchString("/"+room) {
			return "", errors.New("введите ID созданной встречи выбранного сервиса")
		}
		return room, nil
	case "jitsi":
	default:
		return "", errors.New("неизвестный сервис olcRTC")
	}
	u, err := url.Parse(room)
	if err == nil && (u.Path == "" || u.Path == "/") {
		var suffix [16]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", err
		}
		u.Path = "/vpnguard-" + hex.EncodeToString(suffix[:])
		room = u.String()
	}
	if err != nil || len(room) > 512 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !olcRoomPath.MatchString(u.EscapedPath()) {
		return "", errors.New("введите HTTPS-ссылку на отдельную комнату Jitsi")
	}
	return room, nil
}

func createOlcPeer(name, provider, room string) error {
	if !olcPeerID.MatchString(name) {
		return errors.New("имя устройства: 1–32 символа A–Z, a–z, 0–9, дефис и подчёркивание")
	}
	if provider == "" {
		provider = "jitsi"
	}
	room, err := olcRoomID(provider, room)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(olcDir(), 0700); err != nil {
		return err
	}
	peers, err := os.ReadDir(olcDir())
	if err != nil {
		return err
	}
	for _, p := range peers {
		if !strings.HasSuffix(p.Name(), ".yaml") {
			continue
		}
		c, err := readOlcPeer(strings.TrimSuffix(p.Name(), ".yaml"))
		if err != nil {
			return err
		}
		if c.Auth.Provider == provider && strings.EqualFold(c.Room.ID, room) {
			return errors.New("эта комната уже назначена устройству")
		}
	}
	var key [32]byte
	if _, err = rand.Read(key[:]); err != nil {
		return err
	}
	var c olcConfig
	c.Mode = "srv"
	c.Auth.Provider = provider
	c.Room.ID = room
	c.Net.Transport = "vp8channel"
	if provider == "jitsi" {
		c.Net.Transport = "datachannel"
	}
	c.Net.DNS = "1.1.1.1:53"
	c.Crypto.Key = hex.EncodeToString(key[:])
	f, err := os.CreateTemp(olcDir(), ".new-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = json.NewEncoder(f).Encode(c)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Link(f.Name(), filepath.Join(olcDir(), name+".yaml")); os.IsExist(err) {
		return errors.New("имя клиента уже используется")
	}
	return err
}

func (m *olcServer) Tick() { m.tk.Lock(); defer m.tk.Unlock(); m.refresh() }
func (m *olcServer) refresh() {
	entries, err := os.ReadDir(olcDir())
	m.rows = nil
	if err != nil && !os.IsNotExist(err) {
		m.setSt(2, false, "Ошибка чтения профилей", err.Error())
		return
	}
	states := map[string]string{}
	var listErr bool
	if len(entries) > 0 {
		out, code := run("systemctl", "list-units", "--all", "--plain", "--no-legend", "vpnguard-olcrtc-peer@*.service")
		listErr = code != 0
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) >= 4 {
				states[f[0]] = f[2]
			}
		}
	}
	running, failed := 0, 0
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".yaml")
		if !ok || !olcPeerID.MatchString(name) {
			continue
		}
		state := "Остановлен"
		switch states[olcUnit(name)] {
		case "active":
			state = "Служба запущена"
			running++
		case "activating", "deactivating", "reloading":
			state = "Переходное состояние"
		case "failed":
			state = "Сбой службы"
			failed++
		}
		if listErr {
			state = "Состояние неизвестно"
		}
		m.rows = append(m.rows, []string{name, state})
	}
	switch {
	case !olcInstalled():
		m.setSt(-1, false, "Требуется бинарник olcRTC", "Нажмите «Установить olcRTC» или запустите службу устройства")
	case listErr || failed > 0:
		m.setSt(1, running > 0, "Проверьте службы устройств", "Состояние каждого экземпляра показано в таблице")
	case running > 0:
		m.setSt(0, true, fmt.Sprintf("Запущено служб: %d из %d", running, len(m.rows)), "")
	default:
		m.setSt(-1, false, "Остановлен", "Добавьте устройство и запустите его сервер")
	}
}
func (*olcServer) Actions() []Action {
	actions := []Action{{ID: "add", Title: "+ Добавить устройство", Args: []Field{
		{Key: "name", Title: "Имя устройства", Type: "text"},
		{Key: "provider", Title: "Сервис", Type: "select", Value: "jitsi", Options: []Opt{{"jitsi", "Jitsi"}, {"telemost", "Яндекс Телемост"}, {"wbstream", "WB Stream"}}},
		{Key: "room", Title: "Комната", Type: "text", Help: "Для Jitsi укажите HTTPS-адрес сервера или комнаты. Для Телемоста введите ID встречи или ссылку telemost.yandex.ru/j/… . Для WB Stream введите ID встречи, созданной на stream.wb.ru."},
	}}}
	if !olcInstalled() {
		actions = append(actions, Action{ID: "install", Title: "Установить olcRTC"})
	}
	return actions
}
func (m *olcServer) Tables() []Table {
	m.tk.Lock()
	defer m.tk.Unlock()
	return []Table{{Title: "Клиенты olcRTC", Cols: []string{"Устройство", "Служба на шлюзе"}, Rows: m.rows, Empty: "Добавьте устройство для выдачи конфигурации.", Note: "Для каждого устройства используются отдельная комната выбранного сервиса и ключ. Запустите службу и передайте конфигурацию на устройство.", Actions: []Action{{ID: "download", Title: "Скачать конфигурацию"}, {ID: "start", Title: "Запустить"}, {ID: "stop", Title: "Остановить"}, {ID: "remove", Title: "Удалить", Danger: true, Confirm: "Остановить службу и отозвать профиль этого устройства?"}}}}
}

func olcSystemctl(args ...string) error {
	out, code := run("systemctl", args...)
	if code != 0 {
		return fmt.Errorf("systemctl %s: %s", args[0], strings.TrimSpace(out))
	}
	return nil
}
func (m *olcServer) Do(id string, a map[string]string) (string, error) {
	if id == "install" {
		if err := ensureOlcInstalled(); err != nil {
			return "", err
		}
		m.Tick()
		return "olcRTC установлен", nil
	}
	if id == "start" && !olcInstalled() {
		if _, err := readOlcPeer(a["row"]); err != nil {
			return "", err
		}
		if err := ensureOlcInstalled(); err != nil {
			return "", err
		}
	}
	m.tk.Lock()
	defer m.tk.Unlock()
	defer m.refresh()
	if id == "add" {
		if err := createOlcPeer(strings.TrimSpace(a["name"]), a["provider"], strings.TrimSpace(a["room"])); err != nil {
			return "", err
		}
		return "Профиль создан", nil
	}
	name := a["row"]
	_, err := readOlcPeer(name)
	if err != nil {
		return "", err
	}
	unit := olcUnit(name)
	switch id {
	case "start":
		old, _ := S.ReadFile(olcTemplate)
		if old != olcPeerUnit {
			if err := S.WriteFile(olcTemplate, olcPeerUnit, 0644); err != nil {
				return "", err
			}
		}
		if err := olcSystemctl("daemon-reload"); err != nil {
			return "", err
		}
		if err := olcSystemctl("enable", "--now", unit); err != nil {
			return "", err
		}
		return "Служба запущена, автозапуск включён", nil
	case "stop", "remove":
		if _, err := S.ReadFile(olcTemplate); err == nil {
			if err := olcSystemctl("disable", "--now", unit); err != nil {
				return "", err
			}
		} else if !os.IsNotExist(err) {
			return "", err
		} else if active(unit) {
			if err := olcSystemctl("stop", unit); err != nil {
				return "", err
			}
		}
		if id == "remove" {
			if err := os.Remove(filepath.Join(olcDir(), name+".yaml")); err != nil {
				return "", err
			}
			return "Профиль удалён", nil
		}
		return "Служба остановлена", nil
	default:
		return "", errors.New("неизвестное действие olcRTC")
	}
}

func (m *olcServer) clientConfig(name string) (string, error) {
	m.tk.Lock()
	defer m.tk.Unlock()
	c, err := readOlcPeer(name)
	if err != nil {
		return "", err
	}
	c.Mode = "cnc"
	c.Socks = &olcSocks{Host: "127.0.0.1", Port: 8808}
	b, err := json.MarshalIndent(c, "", "  ")
	return string(b) + "\n", err
}
