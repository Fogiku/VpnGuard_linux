// Маршруты: профили правил для групп клиентов, правила поверх профиля для отдельного клиента, резерв для каждого выхода.
// Compile превращает всё это в один сценарий nftables (метки пакетов) и команды ip (таблицы маршрутов по меткам).
// Сценарий применяется целиком одной операцией; предыдущий хранится для отката.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Rule struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Preset string `json:"preset,omitempty"`
	Match  string `json:"match,omitempty"` // домены, адреса, сети и порты (udp:27000-27100) через запятую
	Exit   string `json:"exit"`
	Last   bool   `json:"last,omitempty"` // «всё остальное»
}
type Profile struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}
type ExitPolicy struct {
	Reserve string `json:"reserve"`
	IfDown  string `json:"ifDown"` // block | direct
}
type Routes struct {
	Profiles  []Profile             `json:"profiles"`
	Clients   map[string]string     `json:"clients"`   // IP клиента → профиль
	Overrides map[string][]Rule     `json:"overrides"` // IP клиента → правила поверх профиля
	Policy    map[string]ExitPolicy `json:"policy"`
}

var (
	routeApplyDeferred bool
	routesStarting     atomic.Bool
	rt                 Routes
	rtMu               sync.Mutex
	applyMu            sync.Mutex
	appliedIP          string
	applied            string
	previousState      *routeSnapshot
	applyInfo          string
	applyTmr           *time.Timer
	wasDown            sync.Map // выходы, о сбое которых уже записано решение
)

var presets = map[string][2]string{
	"yt":    {"YouTube и Discord", "youtube.com, www.youtube.com, googlevideo.com, ytimg.com, i.ytimg.com, youtu.be, discord.com, discord.gg, discordapp.com, cdn.discordapp.com, gateway.discord.gg"},
	"bank":  {"Банки и госуслуги", "gosuslugi.ru, nalog.gov.ru, online.sberbank.ru, sberbank.ru, tbank.ru, vtb.ru, alfabank.ru"},
	"tg":    {"Telegram", "149.154.160.0/20, 91.108.4.0/22, 91.108.56.0/22, 91.108.8.0/22"},
	"games": {"Игры (UDP 27000–27100)", "udp:27000-27100"},
}

func defaultRoutes() Routes {
	return Routes{Profiles: []Profile{{ID: "p1", Name: "Обычный", Rules: []Rule{
		{ID: "r1", Title: "YouTube и Discord", Preset: "yt", Exit: "zapret"},
		{ID: "r2", Title: "Всё остальное", Exit: "meduza", Last: true}}}},
		Clients: map[string]string{}, Overrides: map[string][]Rule{},
		Policy: map[string]ExitPolicy{"meduza": {"awg", "block"}, "awg": {"meduza", "block"}, "zapret": {"meduza", "block"}}}
}
func loadRoutes() {
	if !loadJSON("routes.json", &rt) || len(rt.Profiles) == 0 {
		rt = defaultRoutes()
	}
	if rt.Clients == nil {
		rt.Clients = map[string]string{}
	}
	if rt.Overrides == nil {
		rt.Overrides = map[string][]Rule{}
	}
	if rt.Policy == nil {
		rt.Policy = map[string]ExitPolicy{}
	}
}

// resolveExit — куда на самом деле пойдёт трафик правила: сам выход, его резерв или действие «если всё упало».
func resolveExit(id string, pol map[string]ExitPolicy) (eff, state, why string) {
	m := mod(id)
	if m == nil || m.Exit() == nil {
		return "block", "bad", "выход «" + id + "» не найден → заблокировано"
	}
	if m.Status().Up {
		return id, "ok", ""
	}
	p := pol[id]
	if r := mod(p.Reserve); r != nil && r.Exit() != nil && r.Status().Up {
		return p.Reserve, "warn", m.Name() + " не отвечает → резерв " + r.Name()
	}
	if p.IfDown == "direct" && mod("direct").Status().Up {
		return "direct", "warn", m.Name() + " не отвечает, резерва нет → напрямую"
	}
	return "block", "bad", m.Name() + " не отвечает, резерва нет → заблокировано"
}

var (
	rePort   = regexp.MustCompile(`^(tcp|udp):(\d{1,5})(-\d{1,5})?$`)
	reDomain = regexp.MustCompile(`^([a-z0-9-]+\.)+[a-z]{2,}$`)
	reID     = regexp.MustCompile(`[^a-zA-Z0-9]`)
)

// parseMatch разбирает условие правила на адреса и выражения портов. Домены превращаются в адреса через DNS.
func parseMatch(text string, resolve bool) (addrs, ports []string, err error) {
	for _, tok := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' }) {
		tok = strings.ToLower(strings.TrimSpace(tok))
		switch {
		case tok == "":
		case rePort.MatchString(tok):
			p := strings.SplitN(tok, ":", 2)
			ports = append(ports, p[0]+" dport "+p[1])
		case net.ParseIP(tok) != nil && strings.Contains(tok, "."):
			addrs = append(addrs, tok)
		case strings.Contains(tok, "/"):
			if _, _, e := net.ParseCIDR(tok); e != nil || !strings.Contains(tok, ".") {
				return nil, nil, errors.New("неверная сеть: " + tok)
			}
			addrs = append(addrs, tok)
		case reDomain.MatchString(tok):
			if resolve {
				if routingDNS != nil && cfgBool("dns.enabled", true) {
					addrs = append(addrs, routingDNS.lookup(tok)...)
				} else {
					addrs = append(addrs, S.Resolve(tok)...)
				}
			}
		default:
			return nil, nil, errors.New("не понимаю «" + tok + "»: нужен домен, адрес, сеть или порт вида udp:27000-27100")
		}
	}
	sort.Strings(addrs)
	return addrs, ports, nil
}
func matchText(r Rule) string {
	if p, ok := presets[r.Preset]; ok {
		if r.Preset == "yt" {
			return p[1] + ", " + strings.ReplaceAll(cfg("zapret.hosts", ""), "\n", ", ")
		}
		return p[1]
	}
	return r.Match
}
func validateRoutes(r *Routes) error {
	names := map[string]bool{}
	for _, p := range r.Profiles {
		n := strings.ToLower(strings.TrimSpace(p.Name))
		if n == "" || names[n] {
			return errors.New("названия профилей должны быть непустыми и разными")
		}
		names[n] = true
		if len(p.Rules) == 0 || !p.Rules[len(p.Rules)-1].Last {
			return errors.New("профиль «" + p.Name + "»: последним должно быть правило «Всё остальное»")
		}
	}
	if len(r.Profiles) == 0 {
		return errors.New("нужен хотя бы один профиль")
	}
	check := func(where string, rules []Rule) error {
		for _, x := range rules {
			if m := mod(x.Exit); m == nil || m.Exit() == nil {
				return errors.New(where + ": у правила «" + x.Title + "» неизвестный выход")
			}
			if _, _, err := parseMatch(matchText(x), false); err != nil {
				return errors.New(where + ", правило «" + x.Title + "»: " + err.Error())
			}
		}
		return nil
	}
	for _, p := range r.Profiles {
		if err := check("профиль «"+p.Name+"»", p.Rules); err != nil {
			return err
		}
	}
	for ip, rules := range r.Overrides {
		if err := check("клиент "+ip, rules); err != nil {
			return err
		}
	}
	return nil
}
func profileOf(ip string) string {
	if p, ok := rt.Clients[ip]; ok {
		for _, x := range rt.Profiles {
			if x.ID == p {
				return p
			}
		}
	}
	return rt.Profiles[0].ID
}

// Compile строит сценарий nftables и команды ip по текущему состоянию выходов.
func Compile() (script string, ipCmds [][]string) {
	reg, resourceErr := resolveRouteRegistry(false)
	if resourceErr != nil {
		return "error_invalid_route_resources\n", nil
	}
	plan := compileRoutes(reg)
	return plan.nft, plan.ipCommands()
}

type compiledRoutes struct {
	nft                 string
	beforeNFT, afterNFT [][]string
}

func (p compiledRoutes) ipCommands() [][]string {
	return append(append([][]string(nil), p.beforeNFT...), p.afterNFT...)
}

func zapretCounterChain(match string) string {
	return fmt.Sprintf(`  chain zapret {
    type filter hook postrouting priority mangle; policy accept;
    %[1]s counter comment "zapret.out"
    %[1]s tcp dport { 80, 443 } ct original packets 1-9 counter queue num 200 bypass comment "zapret.queue.tcp"
    %[1]s udp dport 443 ct original packets 1-9 counter queue num 200 bypass comment "zapret.queue.udp"
  }
`, match)
}

func compileRoutes(reg routeRegistry) compiledRoutes {
	var plan compiledRoutes
	rtMu.Lock()
	defer rtMu.Unlock()
	byOwner := map[string]routeResource{}
	for _, r := range reg.active {
		byOwner[r.Owner] = r
	}
	wg, wan, sub := wgMod.iface(), wanIface(), wgMod.subnet()
	localNetworks, err := parseLocalNetworks(cfg("net.localNetworks", ""))
	if err != nil {
		return compiledRoutes{nft: "error_invalid_local_networks\n"}
	}
	var sets, lines []string
	mark := func(id string) int {
		eff, _, _ := resolveExit(id, rt.Policy)
		return int(byOwner[eff].Mark)
	}
	emit := func(src string, r Rule, tag string) {
		exitMark := mark(r.Exit)
		pin := ""
		if cfgBool("net.pinFlows", false) {
			pin = fmt.Sprintf("ct mark set (ct mark & 0xff00ffff) | 0x%x ", exitMark<<16)
		}
		mk := fmt.Sprintf("counter meta mark set 0x%x %sreturn comment \"%s\"", exitMark, pin, tag)
		if r.Last {
			lines = append(lines, fmt.Sprintf("    %s %s", src, mk))
			return
		}
		addrs, ports, _ := parseMatch(matchText(r), true)
		if len(addrs) == 0 {
			for _, token := range strings.FieldsFunc(matchText(r), func(c rune) bool { return c == ',' || c == '\n' || c == ' ' }) {
				if reDomain.MatchString(strings.ToLower(strings.TrimSpace(token))) {
					lines = append(lines, "    # DNS-условие пока без адресов; правило пропущено")
					return
				}
			}
		}
		dst := ""
		if len(addrs) > 0 {
			name := "m_" + reID.ReplaceAllString(tag, "_")
			sets = append(sets, fmt.Sprintf("  set %s { type ipv4_addr; flags interval; auto-merge; elements = { %s } }", name, strings.Join(addrs, ", ")))
			dst = " ip daddr @" + name
		}
		switch {
		case len(ports) > 0:
			for _, p := range ports {
				lines = append(lines, fmt.Sprintf("    %s%s %s %s", src, dst, p, mk))
			}
		case dst != "":
			lines = append(lines, fmt.Sprintf("    %s%s %s", src, dst, mk))
		default:
			lines = append(lines, "    # правило «"+r.Title+"» пропущено: адреса не определились")
		}
	}
	members := map[string][]string{}
	for _, c := range wgMod.Clients() {
		if c.Off {
			continue
		}
		for _, r := range rt.Overrides[c.IP] {
			emit("ip saddr "+c.IP, r, "ov_"+c.IP+"_"+r.ID)
		}
		p := profileOf(c.IP)
		members[p] = append(members[p], c.IP)
	}
	for _, p := range rt.Profiles {
		if len(members[p.ID]) == 0 {
			continue
		}
		sets = append(sets, fmt.Sprintf("  set c_%s { type ipv4_addr; elements = { %s } }", reID.ReplaceAllString(p.ID, "_"), strings.Join(members[p.ID], ", ")))
		for _, r := range p.Rules {
			emit("ip saddr @c_"+reID.ReplaceAllString(p.ID, "_"), r, p.ID+"_"+r.ID)
		}
	}
	var b strings.Builder
	b.WriteString("# VpnGuard: создано автоматически, вручную не править\ntable inet vpnguard\ndelete table inet vpnguard\ntable inet vpnguard {\n")
	b.WriteString(strings.Join(sets, "\n"))
	flowRestore := ""
	localBypass := ""
	if len(localNetworks) > 0 {
		localBypass = fmt.Sprintf("    ip daddr { %s } meta mark set 0x14 return comment \"local management bypass\"\n", strings.Join(localNetworks, ", "))
	}
	if cfgBool("net.pinFlows", false) {
		// Зарезервированы только биты 16..23 ct mark; остальные биты сохраняются.
		// Восстанавливаем маршрут только на входе от WG, а не для обратных пакетов.
		var marks []string
		for _, r := range reg.reserved {
			if r.Mark <= 0xff {
				marks = append(marks, fmt.Sprintf("0x%08x", r.Mark<<16))
			}
		}
		flowRestore = "    ct mark & 0x00ff0000 { " + strings.Join(marks, ", ") + " } meta mark set (ct mark & 0x00ff0000) >> 16 return\n"
	}
	fmt.Fprintf(&b, "\n  chain classify {\n    type filter hook prerouting priority mangle; policy accept;\n    iifname != \"%s\" return\n%s%s%s\n  }\n", wg, localBypass, flowRestore, strings.Join(lines, "\n"))
	if len(localNetworks) > 0 {
		fmt.Fprintf(&b, "  chain management_output {\n    type route hook output priority mangle; policy accept;\n    meta mark & 0x40000000 != 0 return\n    ip daddr { %s } meta mark set 0x14 comment \"local management bypass\"\n  }\n", strings.Join(localNetworks, ", "))
	}
	b.WriteString("  chain forward {\n    type filter hook forward priority filter; policy accept;\n")
	if len(localNetworks) > 0 {
		fmt.Fprintf(&b, "    meta mark 0x14 ip daddr { %s } return comment \"local management bypass\"\n", strings.Join(localNetworks, ", "))
	}
	fmt.Fprintf(&b, "    meta mark 0x%x counter drop\n", mod("block").Exit().Mark)
	// A missing private-table route can fall through to main before the next health check.
	for _, m := range Mods {
		r := byOwner[m.ID()]
		if r.Table == "" || r.Table == "main" {
			continue
		}
		e := m.Exit()
		if e == nil || e.Iface == "" {
			fmt.Fprintf(&b, "    iifname %q meta mark 0x%x counter drop\n", wg, r.Mark)
			continue
		}
		fmt.Fprintf(&b, "    iifname %q meta mark 0x%x oifname != %q counter drop\n", wg, r.Mark, e.Iface)
	}
	if cfgBool("net.pinFlows", false) {
		// Старый поток при отказе выхода не должен провалиться в main и обойти запрет.
		for _, m := range Mods {
			if e := m.Exit(); e != nil && !e.Block && !m.Status().Up {
				fmt.Fprintf(&b, "    meta mark 0x%x counter drop comment \"pinned exit unavailable\"\n", byOwner[m.ID()].Mark)
			}
		}
		for _, r := range reg.reserved {
			if _, active := byOwner[r.Owner]; !active {
				fmt.Fprintf(&b, "    meta mark 0x%x counter drop comment \"pinned exit removed\"\n", r.Mark)
			}
		}
	}
	b.WriteString("  }\n")
	if z := mod("zapret"); z != nil && z.Status().Up {
		q := fmt.Sprintf("meta mark 0x%x oifname \"%s\"", z.Exit().Mark, wan)
		b.WriteString(zapretCounterChain(q))
	}
	fmt.Fprintf(&b, "  chain nat {\n    type nat hook postrouting priority srcnat; policy accept;\n    ip saddr %s.0/24 oifname != \"%s\" masquerade\n  }\n}\n", sub, wg)
	for _, m := range Mods {
		r := byOwner[m.ID()]
		e := m.Exit()
		if e == nil || e.Iface == "" || e.Block {
			continue
		}
		mk, pref := fmt.Sprintf("0x%x", r.Mark), strconv.Itoa(r.Priority)
		add := []string{"rule", "add", "fwmark", mk, "lookup", r.Table, "priority", pref}
		del := []string{"rule", "del", "from", "all", "fwmark", mk, "lookup", r.Table, "priority", pref}
		if r.Table == "main" {
			plan.afterNFT = append(plan.afterNFT, del, add)
			continue
		}
		if !m.Status().Up {
			continue
		}
		route := []string{"route", "replace", "default", "dev", e.Iface, "table", r.Table}
		if r.Mark >= 0x20 {
			// Publish a new packet mark only after the table and its selector exist.
			plan.beforeNFT = append(plan.beforeNFT, route, add)
		} else {
			plan.afterNFT = append(plan.afterNFT, del, add, route)
		}
	}
	// nfqws2 raw packets must bypass tunnel-wide default routing too.
	plan.afterNFT = append(plan.afterNFT, []string{"rule", "del", "from", "all", "fwmark", "0x40000000/0x40000000", "lookup", "main", "priority", "1201"}, []string{"rule", "add", "fwmark", "0x40000000/0x40000000", "lookup", "main", "priority", "1201"})
	script := b.String()
	// The empty chain travels with the atomic table replacement and with rollback snapshots.
	encoded, _ := json.Marshal([]any{script, plan.beforeNFT, plan.afterNFT})
	marker := fmt.Sprintf("  chain vg_policy_%x { }\n", sha256.Sum256(encoded))
	plan.nft = strings.Replace(script, "table inet vpnguard {\n", "table inet vpnguard {\n"+marker, 1)
	return plan
}

// Apply применяет маршруты, если они изменились. Ошибка nft оставляет прежние правила в силе.
func Apply(reason string) error {
	applyMu.Lock()
	defer applyMu.Unlock()
	err := routeOperation(reason, false, true, func() error { return applyLocked(reason) })
	if errors.Is(err, errRoutePending) {
		routeApplyDeferred = true
	} else if err != nil && !routesStarting.Load() {
		Decide("ERROR", "Маршруты: %v", err)
	}
	return err
}
func applyLocked(reason string) error {
	if routesStarting.Load() {
		return errors.New("ожидается начальная проверка всех модулей; действующие маршруты сохранены")
	}
	reg, err := resolveRouteRegistry(false)
	if err != nil {
		return fmt.Errorf("реестр сетевых ресурсов: %w", err)
	}
	plan := compileRoutes(reg)
	script := plan.nft
	ipBytes, _ := json.Marshal(plan.ipCommands())
	if script == applied && string(ipBytes) == appliedIP {
		return nil
	}
	if out, code := S.Run(20*time.Second, script, "nft", "-c", "-f", "-"); code != 0 {
		return fmt.Errorf("проверка nft: %s", strings.TrimSpace(out))
	}
	change, err := ensureRouteJournal()
	if err != nil {
		return err
	}
	before := change.Before
	if err := markRouteKernelChange(); err != nil {
		return err
	}
	// snapshotRoutes validated the full selector at each additional priority.
	// Keep an existing match installed while refreshing or changing another exit.
	installed := map[string]bool{}
	for _, rule := range before.rules {
		installed[rule[1]] = true
	}
	for _, c := range plan.beforeNFT {
		if c[0] == "rule" && installed[c[len(c)-1]] {
			continue
		}
		if out, code := run("ip", c...); code != 0 {
			return fmt.Errorf("подготовка дополнительного VPN: ip %v: %s", c, out)
		}
	}
	out, code := S.Run(20*time.Second, script, "nft", "-f", "-")
	if code != 0 {
		Decide("ERROR", "Маршруты: nft отклонил правила (%s) → оставлены прежние. %s", reason, strings.TrimSpace(out))
		return errors.New("nft: " + strings.TrimSpace(out))
	}
	if string(ipBytes) != appliedIP {
		for _, c := range plan.afterNFT {
			if out, code := run("ip", c...); code != 0 && !(len(c) > 1 && c[0] == "rule" && c[1] == "del") {
				cause := fmt.Errorf("ip %v: %s", c, out)
				return cause
			}
		}
	}
	appliedIP = string(ipBytes)
	applied = script
	previousState = before
	applyInfo = time.Now().Format("15:04:05") + " · " + reason
	Log("INFO", "маршруты применены: %s", reason)
	return nil
}
func Rollback() error {
	return RollbackFrom("")
}
func RollbackFrom(requester string) error {
	applyMu.Lock()
	defer applyMu.Unlock()
	return routeOperation("ручной откат", true, false, func() error {
		activeRouteChange.Requester = requester
		last, err := readRouteChange(routeLastFile)
		if err != nil {
			return errors.New("предыдущего набора правил нет")
		}
		if _, err := ensureRouteJournal(); err != nil {
			return err
		}
		if err := markRouteKernelChange(); err != nil {
			return err
		}
		if err := last.Before.restore(); err != nil {
			return err
		}
		if err := restoreRouteConfiguration(last); err != nil {
			return err
		}
		if !last.RoutesExisted {
			if err := saveJSON("routes.json", last.Model); err != nil {
				return err
			}
		}
		applied, appliedIP = "", ""
		applyInfo = time.Now().Format("15:04:05") + " · откат, проверяется связь"
		return nil
	})
}

// applySoon собирает частые события (несколько выходов упали разом) в одно применение.
func applySoon(reason string) {
	rtMu.Lock()
	defer rtMu.Unlock()
	if applyTmr != nil {
		applyTmr.Stop()
	}
	applyTmr = time.AfterFunc(700*time.Millisecond, func() { _ = Apply(reason) })
}
func startRoutes() {
	loadRoutes()
	Subscribe(func(ev, data string) {
		if routesStarting.Load() {
			return
		}
		if ev == "exit.changed" || ev == "routes.changed" {
			if ev == "exit.changed" {
				if m := mod(data); m != nil && m.Exit() != nil {
					eff, _, why := resolveExit(data, rt.Policy)
					if why != "" {
						wasDown.Store(data, true)
						Decide("WARN", "Маршруты: %s", why)
					} else if _, was := wasDown.LoadAndDelete(data); was && eff == data {
						Decide("INFO", "Маршруты: %s снова работает → трафик возвращён", m.Name())
					}
				}
			}
			applySoon(ev + " " + data)
		}
	})
	go func() { // адреса доменов меняются — пересобирать раз в 10 минут
		for {
			time.Sleep(10 * time.Minute)
			_ = Apply("обновление адресов доменов")
		}
	}()
}
func setRoutes(n Routes) error {
	return setRoutesFrom(n, "")
}
func setRoutesFrom(n Routes, requester string) error {
	if err := validateRoutes(&n); err != nil {
		return err
	}
	applyMu.Lock()
	defer applyMu.Unlock()
	return routeOperation("изменение маршрутов в веб-интерфейсе", true, true, func() error {
		activeRouteChange.Requester = requester
		change, err := ensureRouteJournal()
		if err != nil {
			return err
		}
		if n.Clients == nil {
			n.Clients = map[string]string{}
		}
		if n.Overrides == nil {
			n.Overrides = map[string][]Rule{}
		}
		if n.Policy == nil {
			n.Policy = map[string]ExitPolicy{}
		}
		rtMu.Lock()
		rt = n
		rtMu.Unlock()
		if routeFingerprint(change.Model) != routeFingerprint(n) {
			if err := applyLocked("изменение в веб-интерфейсе"); err != nil {
				return err
			}
		}
		return saveJSON("routes.json", n)
	})
}

// Названия не влияют на путь пакетов; их изменение не должно трогать ядро.
func routeFingerprint(r Routes) string {
	b, _ := json.Marshal(r)
	var copy Routes
	json.Unmarshal(b, &copy)
	for i := range copy.Profiles {
		copy.Profiles[i].Name = ""
		for j := range copy.Profiles[i].Rules {
			copy.Profiles[i].Rules[j].Title = ""
		}
	}
	for ip, rules := range copy.Overrides {
		for i := range rules {
			rules[i].Title = ""
		}
		copy.Overrides[ip] = rules
	}
	b, _ = json.Marshal(copy)
	return string(b)
}
