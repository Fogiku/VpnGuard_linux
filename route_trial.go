package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed deploy/route_trial.py
var routeTrialWorker string
var routeTrialMu sync.Mutex
var trialMarker = regexp.MustCompile(`chain vg_policy_([a-f0-9]{64}) `)

type routeTrial struct {
	NFT      string     `json:"nft"`
	Before   [][]string `json:"before"`
	After    [][]string `json:"after"`
	WAN      string     `json:"wan"`
	Mark     uint32     `json:"mark"`
	Device   string     `json:"device"`
	Revision string     `json:"revision"`
}

func planRouteTrial(ip, exit string) (routeTrial, error) {
	var trial routeTrial
	if net.ParseIP(ip).To4() == nil {
		return trial, errors.New("выберите IPv4-клиента WireGuard")
	}
	var clients []WgClient
	for _, c := range wgMod.Clients() {
		if c.IP == ip && !c.Off {
			clients = append(clients, c)
			break
		}
	}
	if len(clients) == 0 {
		return trial, errors.New("выберите включённого WG-клиента")
	}
	m := mod(exit)
	if m == nil || !olcVisible(m) {
		return trial, errors.New("выберите доступный выход для проверки маршрута")
	}
	selected := m.Exit()
	if selected == nil || selected.Block || !m.Status().Up {
		return trial, errors.New("выберите доступный выход для проверки маршрута")
	}
	reg, err := resolveRouteRegistry(false)
	if err != nil {
		return trial, err
	}
	// A standalone model prevents even transient changes to live profiles or assignments.
	model := Routes{Profiles: []Profile{{ID: "trial", Name: "Испытание", Rules: []Rule{{ID: "default", Exit: exit, Last: true}}}}}
	plan := compileRouteModel(reg, model, clients)
	marker := trialMarker.FindStringSubmatch(plan.nft)
	if len(marker) != 2 {
		return trial, errors.New("не удалось скомпилировать испытательную политику")
	}
	for _, r := range reg.active {
		if r.Owner != exit {
			continue
		}
		device := selected.Iface
		wan := wanIface()
		if r.Table == "main" {
			device = wan
		}
		if !extraIfaceName.MatchString(wan) || wan == "lo" || !extraIfaceName.MatchString(device) || device == "lo" {
			return trial, errors.New("не определён интерфейс выхода")
		}
		// A health transition during compilation may have changed the effective mark.
		mark := fmt.Sprintf("meta mark set 0x%x ", r.Mark)
		matched := false
		for _, line := range strings.Split(plan.nft, "\n") {
			if strings.HasSuffix(line, `comment "trial_default"`) && strings.Contains(line, mark) {
				matched = true
				break
			}
		}
		if !matched {
			return trial, errors.New("состояние выхода изменилось, повторите проверку")
		}
		return routeTrial{NFT: plan.nft, Before: plan.beforeNFT, After: plan.afterNFT, WAN: wan, Mark: r.Mark, Device: device, Revision: marker[1]}, nil
	}
	return trial, errors.New("выход отсутствует в реестре маршрутов")
}

func previewRoute(ip, exit string) (map[string]string, error) {
	if !routeTrialMu.TryLock() {
		return nil, errors.New("уже идёт проверка маршрута")
	}
	defer routeTrialMu.Unlock()
	trial, err := planRouteTrial(ip, exit)
	if err != nil {
		return nil, err
	}
	result := map[string]string{"client": ip, "exit": exit, "device": trial.Device, "revision": trial.Revision, "mode": "simulator"}
	if Sim {
		return result, nil
	}
	parent, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(trial)
	if err != nil {
		return nil, err
	}
	out, code := S.Run(30*time.Second, string(data), "unshare", "--net", "--", "python3", "-I", "-c", routeTrialWorker, parent)
	if code != 0 || strings.TrimSpace(out) != "verified" {
		return nil, fmt.Errorf("изолированная проверка не завершилась: %s", strings.TrimSpace(out))
	}
	result["mode"] = "kernel"
	return result, nil
}
