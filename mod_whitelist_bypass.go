package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var olcControl sync.RWMutex

const wbUnit = "vpnguard-whitelist-bypass.service"
const wbRoom = "/run/vpnguard-whitelist-bypass/room"

var wbParticipants = regexp.MustCompile(`\btotal=([0-9]+)\s*$`)

type wbServer struct{ base }

func init()                     { Register(&wbServer{}) }
func (*wbServer) ID() string    { return "whitelist-bypass" }
func (*wbServer) Name() string  { return "Whitelist Bypass · Телемост" }
func (*wbServer) Color() string { return "#408985" }
func (*wbServer) Order() int    { return 6 }
func (b *wbServer) Tick() {
	if Sim {
		b.setSt(0, false, "Симуляция", "")
		return
	}
	out, code := run("systemctl", "show", wbUnit, "-p", "ActiveState", "-p", "InvocationID", "-p", "IPIngressBytes", "-p", "IPEgressBytes", "-p", "NRestarts")
	props := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			props[k] = strings.TrimSpace(v)
		}
	}
	if code != 0 || props["ActiveState"] == "" {
		b.setSt(1, false, "Состояние службы недоступно", "")
		return
	}
	active := props["ActiveState"] == "active"
	state := props["ActiveState"]
	level := 0
	var kv [][2]string
	if active {
		state = "Creator запущен"
		if _, err := os.Stat(wbRoom); err == nil {
			state = "Комната создана"
		}
		participants := "нет данных"
		if id := props["InvocationID"]; len(id) == 32 {
			for _, channel := range []struct{ id, label string }{{"pub", "Публикация WebRTC"}, {"sub", "Приём WebRTC"}} {
				pattern := "\\[" + channel.id + "\\] connection state: "
				line, rc := run("journalctl", "--quiet", "--no-pager", "-o", "cat", "-n", "1", "--grep", pattern, "_SYSTEMD_INVOCATION_ID="+id)
				_, v, ok := strings.Cut(line, "["+channel.id+"] connection state: ")
				v = strings.TrimSpace(v)
				if rc != 0 || !ok {
					v = "нет данных"
				}
				kv = append(kv, [2]string{channel.label, v})
				switch v {
				case "closed", "failed", "disconnected", "connecting":
					level = 1
					state = "Медиаканал Телемоста не готов"
					active = false
				}
			}
			log, rc := run("journalctl", "--quiet", "--no-pager", "-o", "cat", "-n", "1", "--grep", "Participant (joined|left):.*total=[0-9]+", "_SYSTEMD_INVOCATION_ID="+id)
			if match := wbParticipants.FindStringSubmatch(strings.TrimSpace(log)); rc == 0 && len(match) == 2 {
				participants = match[1]
			}
		}
		kv = append(kv, [2]string{"Участники по последнему событию", participants})
	}
	for _, pair := range [][2]string{{"Принято службой", "IPIngressBytes"}, {"Передано службой", "IPEgressBytes"}} {
		kv = append(kv, [2]string{pair[0], olcBytes(props[pair[1]])})
	}
	if _, err := strconv.ParseUint(props["NRestarts"], 10, 64); err == nil {
		kv = append(kv, [2]string{"Автоперезапуски", props["NRestarts"]})
	}
	if state == "failed" {
		level = 2
	}
	b.setSt(level, active, state, "Счётчики systemd включают медиатрафик и служебный обмен. Присутствие участника само по себе не подтверждает передачу через VPN.", kv...)

}
func (*wbServer) Actions() []Action {
	return []Action{{ID: "start", Title: "Запустить сервер"}, {ID: "room", Title: "Получить приглашение"}, {ID: "restart", Title: "Пересоздать комнату", Confirm: "Перезапустить сервер и отключить участников?"}, {ID: "stop", Title: "Остановить сервер"}}
}
func (*wbServer) Do(id string, _ map[string]string) (string, error) {
	if Sim {
		return "", fmt.Errorf("требуется Linux-шлюз")
	}
	if id == "room" {
		data, err := os.ReadFile(wbRoom)
		if err != nil {
			return "", fmt.Errorf("приглашение пока недоступно")
		}
		lines := strings.Fields(string(data))
		if len(lines) == 0 || !strings.HasPrefix(lines[len(lines)-1], "https://telemost.yandex.ru/j/") {
			return "", fmt.Errorf("нет приглашения Телемоста")
		}
		return lines[len(lines)-1], nil
	}
	var args []string
	switch id {
	case "start":
		args = []string{"enable", "--now"}
	case "stop":
		args = []string{"disable", "--now"}
	case "restart":
		args = []string{"restart"}
	default:
		return "", fmt.Errorf("неизвестное действие")
	}
	if out, code := run("systemctl", append(args, wbUnit)...); code != 0 {
		return "", fmt.Errorf("systemctl: %s", out)
	}
	return "Готово", nil
}

func olcVisible(m Module) bool {
	return !(m.ID() == "olcrtc-server" || strings.HasPrefix(m.ID(), "olcrtc-out-")) || cfgBool("modules.olc", false)
}
func stopOlcServices() error {
	for _, query := range []string{"list-units", "list-unit-files"} {
		out, code := run("systemctl", query, "--all", "--plain", "--no-legend", "vpnguard-olcrtc-peer@*.service", "vpnguard-olcrtc-adapter.service", "olcrtc-client-test.service")
		if code != 0 {
			return fmt.Errorf("не удалось перечислить службы olcRTC")
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			unit := f[0]
			if unit == "vpnguard-olcrtc-peer@.service" {
				continue
			}
			if !(strings.HasPrefix(unit, "vpnguard-olcrtc-peer@") && strings.HasSuffix(unit, ".service") || unit == "olcrtc-client-test.service" || unit == "vpnguard-olcrtc-adapter.service") {
				continue
			}
			if query == "list-units" {
				if _, c := run("systemctl", "stop", unit); c != 0 {
					return fmt.Errorf("не удалось остановить %s", unit)
				}
			} else if strings.HasPrefix(f[1], "enabled") {
				if _, c := run("systemctl", "disable", unit); c != 0 {
					return fmt.Errorf("не удалось отключить автозапуск %s", unit)
				}
			}
		}
	}
	return nil
}
