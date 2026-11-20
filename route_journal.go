package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

//go:embed deploy/route_guard.py
var routeGuardSource []byte

const routePendingFile = "routes-pending.json"
const routeLastFile = "routes-last.json"

var errRoutePending = errors.New("предыдущая смена маршрутов ещё ожидает подтверждения или восстановления")

type routeChange struct {
	ID            string             `json:"id"`
	Reason        string             `json:"reason"`
	Status        string             `json:"status"`
	Deadline      int64              `json:"deadline"`
	Timer         string             `json:"timer"`
	Before        *routeSnapshot     `json:"before"`
	Model         Routes             `json:"model"`
	RoutesFile    []byte             `json:"routesFile"`
	RoutesExisted bool               `json:"routesExisted"`
	Network       map[string]*string `json:"network"`
	KernelChanged bool               `json:"kernelChanged"`
	AwaitAck      bool               `json:"awaitAck"`
	KeepLast      bool               `json:"keepLast"`
	Requester     string             `json:"requester"`
}

type routeChangeView struct {
	ID        string `json:"id"`
	Reason    string `json:"reason"`
	Status    string `json:"status"`
	Deadline  int64  `json:"deadline"`
	Requester string `json:"requester"`
}

var activeRouteChange *routeChange
var routeSimulationRunning bool
var routeAgentRunning bool

type routeEvent struct {
	At     string `json:"at"`
	ID     string `json:"id"`
	Reason string `json:"reason"`
	Status string `json:"status"`
}

func routeHistory() []routeEvent {
	var events []routeEvent
	loadJSON("route-events.json", &events)
	if events == nil {
		return []routeEvent{}
	}
	return events
}
func recordRouteEvent(c *routeChange, status string) error {
	events := routeHistory()
	if len(events) > 0 && events[len(events)-1].ID == c.ID && events[len(events)-1].Status == status {
		return nil
	}
	events = append(events, routeEvent{At: time.Now().Format(time.RFC3339), ID: c.ID, Reason: c.Reason, Status: status})
	if len(events) > 50 {
		events = events[len(events)-50:]
	}
	return saveJSON("route-events.json", events)
}

func persistRouteChange(c *routeChange) error {
	if err := saveJSON(routePendingFile, c); err != nil {
		return err
	}
	return syncRouteDirectory()
}
func readRouteChange(name string) (*routeChange, error) {
	b, err := os.ReadFile(filepath.Join(DataDir, name))
	if err != nil {
		return nil, err
	}
	var c routeChange
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.ID == "" || c.Before == nil {
		return nil, errors.New("неполный журнал сетевой операции")
	}
	return &c, nil
}
func pendingRouteView() *routeChangeView {
	c, err := readRouteChange(routePendingFile)
	if err != nil {
		return nil
	}
	return &routeChangeView{ID: c.ID, Reason: c.Reason, Status: c.Status, Deadline: c.Deadline, Requester: c.Requester}
}
func hasRoutePending() bool {
	_, err := os.Stat(filepath.Join(DataDir, routePendingFile))
	return err == nil || !os.IsNotExist(err)
}

// Вызывается лениво, до первого изменения файлов или ядра.
func ensureRouteJournal() (*routeChange, error) {
	c := activeRouteChange
	if c == nil {
		return nil, errors.New("изменение маршрутов вне транзакции")
	}
	if c.Before != nil {
		return c, nil
	}
	before, err := snapshotRoutes()
	if err != nil {
		return nil, err
	}
	rtMu.Lock()
	raw, err := json.Marshal(rt)
	rtMu.Unlock()
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &c.Model); err != nil {
		return nil, err
	}
	c.RoutesFile, err = os.ReadFile(filepath.Join(DataDir, "routes.json"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	c.RoutesExisted = err == nil
	c.Network = map[string]*string{}
	cfgMu.Lock()
	for _, key := range []string{"net.pinFlows", "net.localNetworks"} {
		if value, ok := cfgMap[key]; ok {
			copy := value
			c.Network[key] = &copy
		} else {
			c.Network[key] = nil
		}
	}
	cfgMu.Unlock()
	c.Before = before
	if err := persistRouteChange(c); err != nil {
		return nil, err
	}
	if !Sim {
		if err := saveFile("route-guard.py", routeGuardSource); err != nil {
			return nil, err
		}
		absolute, err := filepath.Abs(DataDir)
		if err != nil {
			return nil, err
		}
		out, code := run("systemd-run", "--quiet", "--unit="+c.Timer, "--on-active=90s", "--timer-property=AccuracySec=1s", "/usr/bin/python3", filepath.Join(absolute, "route-guard.py"), "recover", absolute, c.ID)
		if code != 0 {
			return nil, fmt.Errorf("таймер восстановления маршрутов: %s", out)
		}
	} else if routeSimulationRunning {
		directory, id := DataDir, c.ID
		time.AfterFunc(90*time.Second, func() { recoverSimRouteTimeout(directory, id) })
	}
	return c, nil
}
func markRouteKernelChange() error {
	c, err := ensureRouteJournal()
	if err != nil {
		return err
	}
	c.KernelChanged = true
	err = persistRouteChange(c)
	if err == nil {
		routeCounterRevision.Add(1)
	}
	return err
}

func restoreRouteConfiguration(c *routeChange) error {
	if c.RoutesExisted {
		if err := saveFile("routes.json", c.RoutesFile); err != nil {
			return err
		}
	} else {
		if err := os.Remove(filepath.Join(DataDir, "routes.json")); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	cfgMu.Lock()
	old := map[string]string{}
	for k, v := range cfgMap {
		old[k] = v
	}
	for k, v := range c.Network {
		if v == nil {
			delete(cfgMap, k)
		} else {
			cfgMap[k] = *v
		}
	}
	b, err := json.MarshalIndent(cfgMap, "", "  ")
	if err == nil {
		err = saveFile("config.json", b)
	}
	if err != nil {
		cfgMap = old
	}
	cfgMu.Unlock()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(c.Model)
	if err != nil {
		return err
	}
	var model Routes
	if err = json.Unmarshal(raw, &model); err != nil {
		return err
	}
	rtMu.Lock()
	rt = model
	rtMu.Unlock()
	return syncRouteDirectory()
}

func finishRouteChange(c *routeChange, status string) error {
	if c == nil || c.Before == nil {
		return nil
	}
	c.Status = status
	if err := persistRouteChange(c); err != nil {
		return err
	}
	if status == "committed" && c.KeepLast {
		if err := saveJSON(routeLastFile, c); err != nil {
			return err
		}
		previousState = c.Before
	} else if status == "committed" {
		if err := os.Remove(filepath.Join(DataDir, routeLastFile)); err != nil && !os.IsNotExist(err) {
			return err
		}
		previousState = nil
	}
	if err := recordRouteEvent(c, status); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(DataDir, routePendingFile)); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := syncRouteDirectory(); err != nil {
		return err
	}
	if !Sim {
		run("systemctl", "stop", c.Timer+".timer")
	}
	return nil
}

func recoverSimRouteTimeout(directory, id string) {
	applyMu.Lock()
	defer applyMu.Unlock()
	if !Sim || DataDir != directory {
		return
	}
	c, err := readRouteChange(routePendingFile)
	if err != nil || c.ID != id || c.Status == "committed" || c.Status == "aborted" {
		return
	}
	if c.KernelChanged {
		if err := c.Before.restore(); err != nil {
			return
		}
	}
	if err := restoreRouteConfiguration(c); err != nil {
		return
	}
	applied, appliedIP = "", ""
	finishRouteChange(c, "aborted")
}

// applyMu сериализует модель, flock — агента и отдельный процесс восстановления.
func routeOperation(reason string, awaitAck, keepLast bool, fn func() error) error {
	unlock, err := lockRouteFiles()
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := os.Stat(filepath.Join(DataDir, routePendingFile)); err == nil {
		return errRoutePending
	} else if !os.IsNotExist(err) {
		return err
	}
	c := &routeChange{ID: fmt.Sprint(time.Now().UnixNano()), Reason: reason, Status: "preparing", Deadline: time.Now().Add(90 * time.Second).Unix(), AwaitAck: awaitAck, KeepLast: keepLast}
	c.Timer = "vpnguard-routes-" + c.ID
	activeRouteChange = c
	defer func() { activeRouteChange = nil }()
	if err := fn(); err != nil {
		if c.Before == nil {
			return err
		}
		var restoreErr error
		if c.KernelChanged {
			restoreErr = c.Before.restore()
		}
		restoreErr = errors.Join(restoreErr, restoreRouteConfiguration(c))
		applied, appliedIP = "", ""
		if restoreErr != nil {
			return errors.Join(err, restoreErr)
		}
		if last, err := readRouteChange(routeLastFile); err == nil {
			previousState = last.Before
		} else {
			previousState = nil
		}
		return errors.Join(err, finishRouteChange(c, "aborted"))
	}
	if c.Before == nil {
		return nil
	}
	if awaitAck {
		c.Status = "awaiting_confirmation"
		return persistRouteChange(c)
	}
	return finishRouteChange(c, "committed")
}

func confirmRouteChange(id string) error {
	return confirmRouteChangeFrom(id, "")
}
func confirmRouteChangeFrom(id, requester string) error {
	applyMu.Lock()
	defer applyMu.Unlock()
	unlock, err := lockRouteFiles()
	if err != nil {
		return err
	}
	defer unlock()
	c, err := readRouteChange(routePendingFile)
	if err != nil {
		return err
	}
	if c.ID != id || c.Status != "awaiting_confirmation" {
		return errors.New("сетевой запрос подтверждения устарел")
	}
	if c.Requester != requester {
		return errors.New("подтверждение должно прийти с адреса, изменившего маршруты")
	}
	if time.Now().Unix() >= c.Deadline {
		return errors.New("срок подтверждения истёк; ожидается восстановление")
	}
	if err := finishRouteChange(c, "committed"); err != nil {
		return err
	}
	Decide("INFO", "Маршруты: связь после изменения подтверждена отдельным запросом")
	if routeApplyDeferred {
		routeApplyDeferred = false
		if routeAgentRunning {
			applySoon("состояния выходов после подтверждения")
		}
	}
	return nil
}

func recoverRoutesOnStartup() error {
	c, err := readRouteChange(routePendingFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if Sim {
		if c.Status != "committed" && c.Status != "aborted" {
			if err := restoreRouteConfiguration(c); err != nil {
				return err
			}
			return finishRouteChange(c, "aborted")
		}
		return finishRouteChange(c, c.Status)
	}
	absolute, err := filepath.Abs(DataDir)
	if err != nil {
		return err
	}
	if err := saveFile("route-guard.py", routeGuardSource); err != nil {
		return err
	}
	out, code := run("python3", filepath.Join(absolute, "route-guard.py"), "startup", absolute, c.ID)
	if code != 0 {
		return fmt.Errorf("восстановление незавершённой операции: %s", out)
	}
	return nil
}
