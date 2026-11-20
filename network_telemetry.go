package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Наблюдатель не меняет состояние модулей, не вызывает Apply/Emit и не сбрасывает счётчики.
type qualityTarget struct{ ID, Title, Iface string }
type qualityResult struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Iface       string   `json:"iface"`
	Target      string   `json:"target"`
	At          int64    `json:"at"`
	Sent        int      `json:"sent"`
	Received    int      `json:"received"`
	Loss        *float64 `json:"loss"`
	RTT         *float64 `json:"rtt"`
	Jitter      *float64 `json:"jitter"`
	JitterPairs int      `json:"jitterPairs"`
	Error       string   `json:"error,omitempty"`
}
type ruleCount struct {
	Tag     string  `json:"tag"`
	Title   string  `json:"title"`
	Packets *uint64 `json:"packets"`
	Bytes   *uint64 `json:"bytes"`
}
type ruleCountView struct {
	Revision  uint64      `json:"revision"`
	At        int64       `json:"at"`
	Applied   string      `json:"applied"`
	Rows      []ruleCount `json:"rows"`
	Truncated bool        `json:"truncated"`
	Error     string      `json:"error,omitempty"`
}

var networkTelemetry struct {
	sync.Mutex
	Quality  []qualityResult
	Counters ruleCountView
}
var routeCounterRevision atomic.Uint64
var pingStats = regexp.MustCompile(`(?m)([0-9]+) packets transmitted, ([0-9]+) (?:packets )?received`)
var pingSummary = regexp.MustCompile(`(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)`)
var pingReply = regexp.MustCompile(`icmp_seq=([0-9]+)[^\n]*?time=([0-9]+(?:\.[0-9]+)?) ms`)
var qualityIface = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

func validQualityIP(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && ip.To4() != nil && !strings.Contains(value, ":") && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.Equal(net.IPv4bcast)
}

func parseQualityPing(output string, code, expected int) qualityResult {
	r := qualityResult{}
	x := pingStats.FindStringSubmatch(output)
	if (code != 0 && code != 1) || x == nil {
		r.Error = "ICMP-измерение недоступно: нет полной статистики"
		return r
	}
	r.Sent, _ = strconv.Atoi(x[1])
	r.Received, _ = strconv.Atoi(x[2])
	if r.Sent != expected || r.Sent <= 0 || r.Received < 0 || r.Received > r.Sent {
		r.Error = "ICMP-измерение не завершило заданную серию"
		return r
	}
	loss := 100 * float64(r.Sent-r.Received) / float64(r.Sent)
	r.Loss = &loss
	if r.Received == 0 {
		r.Error = "Нет ICMP-ответов; адрес может фильтровать ping"
		return r
	}
	if summary := pingSummary.FindStringSubmatch(output); summary != nil {
		avg, err := strconv.ParseFloat(summary[2], 64)
		if err == nil && avg >= 0 && !math.IsInf(avg, 0) {
			r.RTT = &avg
		}
	}
	bySequence := map[int]float64{}
	for _, reply := range pingReply.FindAllStringSubmatch(output, -1) {
		seq, _ := strconv.Atoi(reply[1])
		value, err := strconv.ParseFloat(reply[2], 64)
		if err == nil && seq > 0 && seq <= expected && !math.IsInf(value, 0) {
			if _, exists := bySequence[seq]; !exists {
				bySequence[seq] = value
			}
		}
	}
	var delta float64
	for seq := 2; seq <= expected; seq++ {
		current, ok := bySequence[seq]
		previous, prevOK := bySequence[seq-1]
		if ok && prevOK {
			delta += math.Abs(current - previous)
			r.JitterPairs++
		}
	}
	if r.JitterPairs > 0 {
		jitter := delta / float64(r.JitterPairs)
		r.Jitter = &jitter
	}
	return r
}

func currentQualityTargets() []qualityTarget {
	targets := []qualityTarget{{"direct", "Провайдер (WAN)", wanIface()}}
	for _, m := range Mods {
		if e := m.Exit(); e != nil && e.Table > 0 && e.Iface != "" && m.Status().Up {
			targets = append(targets, qualityTarget{m.ID(), m.Name(), e.Iface})
		}
	}
	return targets
}

func collectQuality() {
	if routesStarting.Load() {
		return
	}
	if !cfgBool("net.qualityEnabled", true) {
		networkTelemetry.Lock()
		networkTelemetry.Quality = nil
		networkTelemetry.Unlock()
		return
	}
	ip := cfg("net.qualityIP", "1.1.1.1")
	targets := currentQualityTargets()
	var results []qualityResult
	for _, target := range targets {
		r := qualityResult{}
		if !validQualityIP(ip) || !qualityIface.MatchString(target.Iface) {
			r.Error = "Для измерения нужны корректные IPv4-адрес и интерфейс"
		} else {
			output, code := S.Run(6*time.Second, "", "env", "LC_ALL=C", "ping", "-4", "-n", "-c", "5", "-i", "0.2", "-W", "1", "-w", "4", "-I", target.Iface, ip)
			r = parseQualityPing(output, code, 5)
		}
		r.ID, r.Title, r.Iface, r.Target, r.At = target.ID, target.Title, target.Iface, ip, time.Now().Unix()
		results = append(results, r)
	}
	// Не публикуем результат старой конфигурации после смены интерфейса или цели.
	if cfg("net.qualityIP", "1.1.1.1") != ip || !cfgBool("net.qualityEnabled", true) {
		return
	}
	current := currentQualityTargets()
	filtered := results[:0]
	for _, result := range results {
		for _, target := range current {
			if result.ID == target.ID && result.Iface == target.Iface {
				filtered = append(filtered, result)
				break
			}
		}
	}
	networkTelemetry.Lock()
	networkTelemetry.Quality = filtered
	networkTelemetry.Unlock()
}

func ruleLabels() map[string]string {
	rtMu.Lock()
	defer rtMu.Unlock()
	labels := map[string]string{}
	title := func(r Rule) string {
		if r.Title != "" {
			return r.Title
		}
		if r.Last {
			return "Всё остальное"
		}
		return r.ID
	}
	for _, p := range rt.Profiles {
		for _, r := range p.Rules {
			labels[p.ID+"_"+r.ID] = p.Name + " / " + title(r)
		}
	}
	for ip, rules := range rt.Overrides {
		for _, r := range rules {
			labels["ov_"+ip+"_"+r.ID] = ip + " / " + title(r)
		}
	}
	return labels
}

func parseRuleCounts(output string, labels map[string]string) ([]ruleCount, bool, error) {
	if len(output) > 4<<20 {
		return nil, false, fmt.Errorf("ответ nft превышает 4 МиБ")
	}
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Family  string `json:"family"`
				Table   string `json:"table"`
				Chain   string `json:"chain"`
				Comment string `json:"comment"`
				Expr    []struct {
					Counter *struct {
						Packets uint64 `json:"packets"`
						Bytes   uint64 `json:"bytes"`
					} `json:"counter"`
				} `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(output), &doc); err != nil {
		return nil, false, fmt.Errorf("не удалось разобрать счётчики nft: %w", err)
	}
	type totals struct{ packets, bytes uint64 }
	found := map[string]totals{}
	for _, entry := range doc.Nftables {
		r := entry.Rule
		if r == nil || r.Family != "inet" || r.Table != "vpnguard" || r.Chain != "classify" {
			continue
		}
		if _, ok := labels[r.Comment]; !ok {
			continue
		}
		for _, expr := range r.Expr {
			if expr.Counter != nil {
				old := found[r.Comment]
				count := expr.Counter
				if ^uint64(0)-old.packets < count.Packets || ^uint64(0)-old.bytes < count.Bytes {
					return nil, false, fmt.Errorf("переполнение счётчика nft")
				}
				found[r.Comment] = totals{old.packets + count.Packets, old.bytes + count.Bytes}
			}
		}
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	truncated := len(keys) > 256
	if truncated {
		keys = keys[:256]
	}
	rows := make([]ruleCount, 0, len(keys))
	for _, key := range keys {
		r := ruleCount{Tag: key, Title: labels[key]}
		if count, ok := found[key]; ok {
			packets, bytes := count.packets, count.bytes
			r.Packets, r.Bytes = &packets, &bytes
		}
		rows = append(rows, r)
	}
	return rows, truncated, nil
}

func collectRuleCounts() {
	if routesStarting.Load() || !applyMu.TryLock() {
		return
	}
	defer applyMu.Unlock()
	view := ruleCountView{At: time.Now().Unix(), Applied: applyInfo, Revision: routeCounterRevision.Load(), Rows: []ruleCount{}}
	output, code := S.Run(3*time.Second, "", "nft", "-j", "list", "table", "inet", "vpnguard")
	if code != 0 {
		view.Error = "Не удалось прочитать счётчики nft"
	} else {
		rows, truncated, err := parseRuleCounts(output, ruleLabels())
		if err != nil {
			view.Error = err.Error()
		} else {
			view.Rows, view.Truncated = rows, truncated
		}
	}
	networkTelemetry.Lock()
	networkTelemetry.Counters = view
	networkTelemetry.Unlock()
}

func networkTelemetryView() map[string]any {
	networkTelemetry.Lock()
	defer networkTelemetry.Unlock()
	quality := append([]qualityResult{}, networkTelemetry.Quality...)
	return map[string]any{"quality": quality, "qualityEnabled": cfgBool("net.qualityEnabled", true), "counters": networkTelemetry.Counters, "countersCurrent": networkTelemetry.Counters.Revision == routeCounterRevision.Load()}
}

func networkHistoryValues(values map[string]float64, now int64) {
	current := map[string]string{}
	for _, target := range currentQualityTargets() {
		current[target.ID] = target.Iface
	}
	networkTelemetry.Lock()
	defer networkTelemetry.Unlock()
	if cfgBool("net.qualityEnabled", true) {
		for _, r := range networkTelemetry.Quality {
			if now-r.At <= 45 && now >= r.At && r.Target == cfg("net.qualityIP", "1.1.1.1") && current[r.ID] == r.Iface {
				for key, value := range map[string]*float64{"rtt_ms": r.RTT, "jitter_ms": r.Jitter, "loss_pct": r.Loss} {
					if value != nil {
						values["quality."+r.ID+"."+key] = *value
					}
				}
			}
		}
	}
	counts := networkTelemetry.Counters
	if counts.Revision == routeCounterRevision.Load() && counts.Applied != "" && counts.Error == "" && now-counts.At <= 20 && now >= counts.At {
		for _, r := range counts.Rows {
			if r.Packets != nil && r.Bytes != nil {
				values["rule."+r.Tag+".packets"] = float64(*r.Packets)
				values["rule."+r.Tag+".bytes"] = float64(*r.Bytes)
			}
		}
	}
}

func startNetworkTelemetry() {
	go func() {
		for {
			collectRuleCounts()
			time.Sleep(10 * time.Second)
		}
	}()
	go func() {
		time.Sleep(10 * time.Second)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			collectQuality()
			<-ticker.C
		}
	}()
}
