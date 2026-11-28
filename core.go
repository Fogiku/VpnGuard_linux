// VpnGuard для Linux — ядро: настройки, журнал, журнал решений, события, ограничитель повторов.
package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const Version = "1.9.64"

var (
	DataDir string
	Sim     bool
	S       Sys
	cfgMu   sync.Mutex
	cfgMap  = map[string]string{}
	logMu   sync.Mutex
	logRing []LogLine
	decRing []LogLine
	subsMu  sync.RWMutex
	subs    []func(ev, data string)
	limMu   sync.Mutex
	limits  = map[string][]time.Time{}
)

type LogLine struct {
	T    string `json:"t"`
	Lvl  string `json:"lvl"` // INFO, WARN, ERROR
	Text string `json:"text"`
}

func loadCfg() {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	if b, err := os.ReadFile(filepath.Join(DataDir, "config.json")); err == nil {
		var loaded map[string]string
		if json.Unmarshal(b, &loaded) == nil {
			cfgMap = loaded
			if cfgMap == nil {
				cfgMap = map[string]string{}
			}
		}
	}
}
func cfg(key, def string) string {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	if v, ok := cfgMap[key]; ok {
		return v
	}
	return def
}
func cfgInt(key string, def int) int {
	if n, err := strconv.Atoi(cfg(key, "")); err == nil {
		return n
	}
	return def
}
func cfgBool(key string, def bool) bool {
	v := cfg(key, "")
	if v == "" {
		return def
	}
	return v == "true" || v == "1"
}
func setCfg(key, val string) error {
	return setConfigValues(map[string]string{key: val})
}

func setConfigValues(values map[string]string) error {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	next := maps.Clone(cfgMap)
	maps.Copy(next, values)
	if err := saveJSON("config.json", next); err != nil {
		return err
	}
	cfgMap = next
	return nil
}

// delCfg — вернуть настройку к значению по умолчанию.
func delCfg(key string) error {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	old, had := cfgMap[key]
	delete(cfgMap, key)
	b, _ := json.MarshalIndent(cfgMap, "", "  ")
	if err := saveFile("config.json", b); err != nil {
		if had {
			cfgMap[key] = old
		}
		Log("ERROR", "config.json: %v", err)
		return err
	}
	return nil
}
func saveFile(name string, b []byte) error {
	p := filepath.Join(DataDir, name)
	f, err := os.CreateTemp(filepath.Dir(p), "."+filepath.Base(p)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0o600); err == nil {
		_, err = f.Write(b)
	}
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
	return os.Rename(tmp, p)
}
func loadJSON(name string, v any) bool {
	b, err := os.ReadFile(filepath.Join(DataDir, name))
	return err == nil && json.Unmarshal(b, v) == nil
}
func saveJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return saveFile(name, b)
}

func push(ring *[]LogLine, max int, l LogLine) {
	*ring = append(*ring, l)
	if len(*ring) > max {
		*ring = (*ring)[len(*ring)-max:]
	}
}

// Log — обычный журнал агента (файл data/logs + последние 500 строк для веба).
func Log(lvl, format string, a ...any) {
	l := LogLine{time.Now().Format("2006-01-02 15:04:05"), lvl, fmt.Sprintf(format, a...)}
	logMu.Lock()
	push(&logRing, 500, l)
	logMu.Unlock()
	dir := filepath.Join(DataDir, "logs")
	_ = os.MkdirAll(dir, 0o755)
	if f, err := os.OpenFile(filepath.Join(dir, "vpnguard-"+time.Now().Format("20060102")+".log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		fmt.Fprintf(f, "%s [%s] %s\n", l.T, l.Lvl, l.Text)
		f.Close()
	}
}

// Decide — журнал решений: что агент увидел и что сделал. Это основа «детального поиска проблем».
func Decide(lvl, format string, a ...any) {
	l := LogLine{time.Now().Format("2006-01-02 15:04:05"), lvl, fmt.Sprintf(format, a...)}
	logMu.Lock()
	push(&decRing, 200, l)
	logMu.Unlock()
	Log(lvl, "решение: %s", l.Text)
}
func snapshotLog(ring *[]LogLine) []LogLine {
	logMu.Lock()
	defer logMu.Unlock()
	out := make([]LogLine, len(*ring))
	copy(out, *ring)
	return out
}

// События между модулями: tunnel.down, tunnel.up, exit.changed, routes.changed …
func Subscribe(f func(ev, data string)) {
	subsMu.Lock()
	subs = append(subs, f)
	subsMu.Unlock()
}
func Emit(ev, data string) {
	controllerEvents.record(ev, data)
	subsMu.RLock()
	defer subsMu.RUnlock()
	for _, f := range subs {
		go f(ev, data)
	}
}

// allow — не больше n действий key за окно win (например, 5 перезапусков службы за 30 минут).
func allow(key string, n int, win time.Duration) bool {
	limMu.Lock()
	defer limMu.Unlock()
	now := time.Now()
	var keep []time.Time
	for _, t := range limits[key] {
		if now.Sub(t) < win {
			keep = append(keep, t)
		}
	}
	if len(keep) >= n {
		limits[key] = keep
		return false
	}
	limits[key] = append(keep, now)
	return true
}
