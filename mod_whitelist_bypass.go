package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

var olcControl sync.RWMutex

const wbUnit = "vpnguard-whitelist-bypass.service"
const wbRoom = "/run/vpnguard-whitelist-bypass/room"

type wbServer struct{ base }

func init()                     { Register(&wbServer{}) }
func (*wbServer) ID() string    { return "whitelist-bypass" }
func (*wbServer) Name() string  { return "Whitelist Bypass · Телемост" }
func (*wbServer) Color() string { return "#408985" }
func (*wbServer) Order() int    { return 6 }
func (b *wbServer) Tick() {
	active := false
	state := "Служба остановлена"
	if !Sim {
		if _, code := run("systemctl", "is-active", "--quiet", wbUnit); code == 0 {
			active = true
			state = "Creator запущен"
			if _, err := os.Stat(wbRoom); err == nil {
				state = "Комната создана"
			}
		}
	} else {
		state = "Симуляция"
	}
	b.setSt(0, active, state, "Подключение клиента проверяется передачей данных через комнату.")

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
