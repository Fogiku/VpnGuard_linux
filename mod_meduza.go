// Модуль MeduzaVPN: служба meduzavpnd и CLI meduzavpn.
// Вход по QR (картинкой) и по почте с паролем, выход, устройства аккаунта; VPN (страна) с пингом до сервера, протокол;
// подключение, тест протоколов, лестница восстановления с автоподбором протокола; настройки самой службы
// (kill switch, раздельное туннелирование, DNS, MTU …); версия и обновление CLI; журнал службы; проверки.
// Команды и поля ответов взяты из справки CLI 1.2.80 (meduzavpn <команда> --help), разбор терпимый:
// на стенде с настоящей службой их нужно сверить — см. README, раздел «Что проверить на стенде».
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type mdzItem struct {
	ID, Name, Info string
	Host           string // адрес сервера (host:port), если CLI его отдаёт
}
type mdzPing struct {
	Host string  `json:"host"`
	Ms   float64 `json:"ms"` // -1 — не отвечает
	How  string  `json:"how"`
	At   string  `json:"at"`
}
type mdzTest struct {
	Proto, Name, Result, Err string
	OK                       bool
	ConnSec                  float64
	Ms                       int
}
type mdzLogin struct {
	Running bool
	URL     string
	Code    string
	Until   time.Time
	Result  string // итог последней попытки входа
	Bad     bool
}
type meduza struct {
	loginWork sync.WaitGroup // завершение обновления состояния после входа
	base
	fails          int
	override       string // запасной протокол, найденный автоподбором
	ovAt           time.Time
	fbAt           time.Time // последний перебор протоколов
	services       []mdzItem
	protos         []mdzItem
	devices        [][]string
	catAt          time.Time
	catErr         string
	out            string // вывод последней служебной команды (журнал службы)
	outTitle       string
	tests          []mdzTest
	testAt         string
	iface          string
	rx             rate
	signed         bool
	conn           bool
	curProto       string
	account        string
	st             map[string]any // последний ответ status --json
	dcfg           map[string]any // /etc/meduzavpn/config.json
	lmu            sync.Mutex
	locationUntil  time.Time
	locationChange sync.Mutex
	lg             mdzLogin
	pmu            sync.Mutex
	pingRun        sync.Mutex
	pings          map[string]mdzPing // по id VPN
	pingAt         time.Time
	ver            string
	remote         string
	remoteAt       time.Time
	updating       bool
	restarts       []time.Time
	restartN       int
	lastRst        time.Time
	lastRstWhy     string
}

const mdzConfPath = "/etc/meduzavpn/config.json"

func init()                     { Register(&meduza{pings: map[string]mdzPing{}}) }
func (m *meduza) ID() string    { return "meduza" }
func (m *meduza) Name() string  { return "MeduzaVPN" }
func (m *meduza) Color() string { return "#39d0ff" }
func (m *meduza) Order() int    { return 10 }
func (m *meduza) proto() string {
	if m.override != "" {
		return m.override
	}
	return cfg("meduza.protocol", "ultra")
}
func (m *meduza) cli(args ...string) (string, int) {
	return S.Run(time.Duration(cfgInt("meduza.connectTimeoutSec", 90)+30)*time.Second, "", "meduzavpn", args...)
}

// pickStr — первое непустое значение из полей с известными именами.
func pickStr(d map[string]any, names ...string) string {
	for _, n := range names {
		if v, ok := d[n]; ok && v != nil {
			s := fmt.Sprint(v)
			if f, isF := v.(float64); isF {
				s = strconv.FormatFloat(f, 'f', -1, 64)
			}
			if s != "" {
				return s
			}
		}
	}
	return ""
}

// jsonArr достаёт массив из JSON вида [..] или {"services":[..]}; prefer — какое поле взять, если массивов несколько.
func jsonArr(text, prefer string) []any {
	var raw any
	if json.Unmarshal([]byte(strings.TrimSpace(text)), &raw) != nil {
		return nil
	}
	if a, ok := raw.([]any); ok {
		return a
	}
	obj, _ := raw.(map[string]any)
	if a, ok := obj[prefer].([]any); ok {
		return a
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if a, ok := obj[k].([]any); ok {
			return a
		}
	}
	return nil
}

// pickList — список VPN или протоколов; у элементов берётся первое непустое из известных имён полей.
func pickList(text, prefer string) []mdzItem {
	var out []mdzItem
	for _, x := range jsonArr(text, prefer) {
		switch d := x.(type) {
		case string:
			out = append(out, mdzItem{ID: d, Name: d})
		case map[string]any:
			if av, ok := d["available"].(bool); ok && !av {
				continue
			}
			id := pickStr(d, "id", "service_id", "slug", "key", "name", "protocol")
			name := pickStr(d, "title", "display_name", "service_name", "name", "location", "country", "id")
			var info []string
			for _, k := range []string{"country", "location", "city", "description", "engine", "status"} {
				if v := pickStr(d, k); v != "" && v != name && len(info) < 2 {
					info = append(info, v)
				}
			}
			out = append(out, mdzItem{ID: id, Name: name, Info: strings.Join(info, ", "), Host: pickStr(d, "endpoint", "server", "host", "address", "hostname", "ip", "ipv4", "ipv6")})
		}
	}
	return out
}

// CLI 1.2.80 reports state instead of connected, and may omit interface.
func meduzaConnected(st map[string]any) bool {
	if connected, ok := st["connected"].(bool); ok {
		return connected
	}
	return pickStr(st, "state") == "connected"
}

func meduzaIface(st map[string]any) string {
	if name := pickStr(st, "interface"); name != "" {
		return name
	}
	if name := cfg("meduza.iface", ""); name != "" {
		return name
	}
	for _, name := range []string{"meduza0", "mdz0"} {
		if _, err := S.ReadFile("/sys/class/net/" + name + "/ifindex"); err == nil {
			return name
		}
	}
	return "meduza0"
}
func (m *meduza) readStatus() bool {
	out, code := m.cli("status", "--json")
	if code != 0 {
		return false
	}
	var st map[string]any
	if json.Unmarshal([]byte(out), &st) != nil {
		return false
	}
	b := func(k string) bool { v, _ := st[k].(bool); return v }
	m.mu.Lock()
	m.st = st
	m.signed, m.conn = b("signed_in"), meduzaConnected(st)
	m.curProto = pickStr(st, "protocol")
	m.account = pickStr(st, "signed_in_as", "email")
	m.iface = meduzaIface(st)
	m.mu.Unlock()
	if rx, err := strconv.ParseFloat(pickStr(st, "rx_bytes"), 64); err == nil {
		m.metric("rx", m.rx.bps(rx))
	}
	// адрес сервера подключённого VPN — бесплатный источник для пинга
	if ep, svc := pickStr(st, "endpoint"), pickStr(st, "service"); ep != "" && svc != "" {
		m.pmu.Lock()
		p := m.pings[svc]
		if p.Host == "" {
			p.Host, p.Ms = ep, -2
			m.pings[svc] = p
		}
		m.pmu.Unlock()
	}
	return true
}
func (m *meduza) readDaemonCfg() {
	t, err := S.ReadFile(mdzConfPath)
	d := map[string]any{}
	if err == nil {
		_ = json.Unmarshal([]byte(t), &d)
	}
	m.mu.Lock()
	m.dcfg = d
	m.mu.Unlock()
}
func (m *meduza) catalog(force bool) {
	if !force && time.Since(m.catAt) < time.Minute && len(m.protos) > 0 && len(m.services) > 0 {
		return
	}
	m.catAt = time.Now()
	var errs []string
	sv, c1 := m.cli("list", "--services", "--json")
	if c1 == 0 {
		m.services = pickList(sv, "services")
		m.pmu.Lock()
		for _, service := range m.services {
			p := m.pings[service.ID]
			if service.Host != "" && p.Host != service.Host {
				m.pings[service.ID] = mdzPing{Host: service.Host, Ms: -2}
			}
		}
		m.pmu.Unlock()
	} else {
		errs = append(errs, fmt.Sprintf("list --services: код %d %s", c1, firstLine(sv)))
	}
	pr, c2 := m.cli("list", "--protocols", "--json")
	if c2 == 0 {
		m.protos = pickList(pr, "protocols")
	} else {
		errs = append(errs, fmt.Sprintf("list --protocols: код %d %s", c2, firstLine(pr)))
	}
	m.catErr = strings.Join(errs, "; ")
	m.readDevices()
	Log("INFO", "MeduzaVPN: список VPN — %d, протоколов — %d%s", len(m.services), len(m.protos), map[bool]string{true: " (" + m.catErr + ")", false: ""}[m.catErr != ""])
	go m.pingAll(false)
}
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}
func (m *meduza) readDevices() {
	out, code := m.cli("devices", "list", "--json")
	if code != 0 {
		return
	}
	var rows [][]string
	for _, x := range jsonArr(out, "devices") {
		d, ok := x.(map[string]any)
		if !ok {
			continue
		}
		cur := ""
		if v, _ := d["current"].(bool); v {
			cur = "это устройство (шлюз)"
		}
		rows = append(rows, []string{pickStr(d, "id", "sid"), pickStr(d, "device_name", "name", "label"), pickStr(d, "platform"), pickStr(d, "app_version"),
			pickStr(d, "ip"), pickStr(d, "login_method"), pickStr(d, "last_seen_at", "created_at"), cur})
	}
	m.mu.Lock()
	m.devices = rows
	m.mu.Unlock()
}

// ---------------------------------------------------------------- пинг до серверов
var (
	reEndpoint = regexp.MustCompile(`(?mi)^\s*Endpoint\s*=\s*(\S+)`)
	reRemote   = regexp.MustCompile(`(?mi)^\s*remote\s+(\S+)\s+(\d+)`)
	reServerY  = regexp.MustCompile(`(?mi)^\s*server:\s*["']?([^\s"']+)`)
	reURLHost  = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^@\s/]+@(\[[0-9a-f:]+\]|[^:/?#\s\[]+):(\d+)`)
	reRtt      = regexp.MustCompile(`=\s*[\d.]+/([\d.]+)/`)
)

// profileHost — адрес сервера из профиля подключения: конфигурация WireGuard/AmneziaWG (Endpoint), .ovpn (remote),
// YAML Hysteria (server:), ссылка vless://…@host:port, JSON с config_text/config_base64 или адресом сервера.
func profileHost(text string) string {
	var d map[string]any
	if json.Unmarshal([]byte(strings.TrimSpace(text)), &d) == nil {
		if t := pickStr(d, "config_text"); t != "" {
			return profileHost(t)
		}
		if b := pickStr(d, "config_base64"); b != "" {
			if raw, err := base64.StdEncoding.DecodeString(b); err == nil {
				return profileHost(string(raw))
			}
		}
		if h := pickStr(d, "endpoint", "server", "address", "host"); h != "" {
			return h
		}
	}
	if x := reEndpoint.FindStringSubmatch(text); x != nil {
		return x[1]
	}
	if x := reRemote.FindStringSubmatch(text); x != nil {
		return net.JoinHostPort(x[1], x[2])
	}
	if x := reURLHost.FindStringSubmatch(text); x != nil {
		return net.JoinHostPort(strings.Trim(x[1], "[]"), x[2])
	}
	if x := reServerY.FindStringSubmatch(text); x != nil {
		return x[1]
	}
	return ""
}

// measure — задержка до сервера в обход туннелей: ICMP с интерфейса провайдера, если ICMP закрыт — время TCP-соединения.
func measure(hostport string) (float64, string) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, ""
	}
	w := wanIface()
	out, code := S.Run(10*time.Second, "", "ping", "-n", "-q", "-c", "3", "-W", "2", "-I", w, host)
	if x := reRtt.FindStringSubmatch(out); code == 0 && x != nil {
		v, _ := strconv.ParseFloat(x[1], 64)
		return v, "ICMP"
	}
	if port != "" {
		out, _ = S.Run(6*time.Second, "", "curl", "-s", "-o", "/dev/null", "-w", "%{time_connect}", "--connect-timeout", "3", "--max-time", "4", "--interface", w, "http://"+net.JoinHostPort(host, port)+"/")
		if v, err := strconv.ParseFloat(strings.TrimSpace(out), 64); err == nil && v > 0 {
			return v * 1000, "TCP"
		}
	}
	return -1, ""
}

// pingAll — пинг до сервера каждого VPN. Адрес берётся из списка VPN, из status (подключённый VPN)
// или из профиля подключения (meduzavpn profile); найденный адрес запоминается, профиль повторно не запрашивается.
func (m *meduza) pingAll(rediscover bool) {
	if !m.pingRun.TryLock() { // уже идёт
		return
	}
	defer m.pingRun.Unlock()
	m.pmu.Lock()
	loaded := len(m.pings) > 0
	m.pmu.Unlock()
	if !loaded {
		saved := map[string]mdzPing{}
		if loadJSON("meduza-ping.json", &saved) {
			m.pmu.Lock()
			for k, v := range saved {
				if _, ok := m.pings[k]; !ok {
					m.pings[k] = v
				}
			}
			m.pmu.Unlock()
		}
	}
	m.busy("пинг до серверов")
	defer m.busy("")
	for _, s := range m.services {
		m.pmu.Lock()
		p := m.pings[s.ID]
		m.pmu.Unlock()
		if s.Host != "" {
			p.Host = s.Host
		}
		if p.Host == "" || rediscover {
			out, code := m.cli("profile", "--service", s.ID, "--protocol", m.proto())
			if h := profileHost(out); code == 0 && h != "" {
				p.Host = h
			}
		}
		if p.Host == "" {
			p.Ms, p.How = -1, "адрес сервера не найден"
		} else {
			p.Ms, p.How = measure(p.Host)
		}
		p.At = time.Now().Format("15:04")
		m.pmu.Lock()
		// Do not overwrite a refreshed location with an old in-flight probe.
		if current := m.pings[s.ID]; current.Host == "" || current.Host == p.Host {
			m.pings[s.ID] = p
		}
		m.pmu.Unlock()
	}
	m.pmu.Lock()
	m.pingAt = time.Now()
	saveJSON("meduza-ping.json", m.pings)
	m.pmu.Unlock()
}
func (m *meduza) pingText(id string) string {
	m.pmu.Lock()
	p, ok := m.pings[id]
	m.pmu.Unlock()
	switch {
	case !ok || p.Ms == -2:
		return "пинг не измерен"
	case p.Ms < 0:
		if p.How != "" {
			return p.How
		}
		return "не отвечает"
	}
	return fmt.Sprintf("%.0f мс", p.Ms)
}

// ---------------------------------------------------------------- вход
var reURL = regexp.MustCompile(`https?://\S+`)

func (m *meduza) loginLine(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	m.lmu.Lock()
	defer m.lmu.Unlock()
	var d map[string]any
	if json.Unmarshal([]byte(line), &d) == nil {
		if u := pickStr(d, "verify_url", "verification_uri_complete", "url", "link"); u != "" {
			m.lg.URL = u
		}
		if c := pickStr(d, "user_code", "code"); c != "" {
			m.lg.Code = c
		}
		if e, err := strconv.Atoi(pickStr(d, "expires_in")); err == nil && e > 0 {
			m.lg.Until = time.Now().Add(time.Duration(e) * time.Second)
		}
		if t := pickStr(d, "error", "message"); t != "" {
			m.lg.Result = t
		}
		return
	}
	if u := reURL.FindString(line); u != "" && m.lg.URL == "" {
		m.lg.URL = u
		return
	}
	if !strings.ContainsAny(line, "█▀▄") { // QR, нарисованный символами в терминале, не нужен
		m.lg.Result = line
	}
}
func (m *meduza) loginQR() (string, error) {
	m.lmu.Lock()
	if m.lg.Running {
		m.lmu.Unlock()
		return "Вход уже ждёт подтверждения — QR-код на странице", nil
	}
	m.lg = mdzLogin{Running: true, Until: time.Now().Add(5 * time.Minute)}
	m.lmu.Unlock()
	m.loginWork.Add(1)
	go func() {
		defer m.loginWork.Done()
		code := S.Stream(10*time.Minute, "", m.loginLine, "meduzavpn", "login", "--qr", "--json")
		m.lmu.Lock()
		m.lg.Running, m.lg.URL, m.lg.Code = false, "", ""
		if code == 0 {
			m.lg.Result, m.lg.Bad = "Вход выполнен", false
		} else {
			if m.lg.Result == "" || m.lg.Result == "Approved." {
				m.lg.Result = fmt.Sprintf("вход не выполнен (код %d)", code)
			}
			if strings.Contains(strings.ToLower(m.lg.Result), "declined") {
				m.lg.Result = "вход отклонён на телефоне"
			}
			m.lg.Bad = true
		}
		res := m.lg.Result
		m.lmu.Unlock()
		Decide(map[bool]string{true: "INFO", false: "WARN"}[code == 0], "MeduzaVPN: вход по QR — %s", res)
		if code == 0 {
			m.readStatus()
			m.catalog(true)
		}
		m.Tick()
	}()
	// подождать ссылку, чтобы QR появился сразу после нажатия
	for i := 0; i < 40; i++ {
		m.lmu.Lock()
		u, run := m.lg.URL, m.lg.Running
		m.lmu.Unlock()
		if u != "" || !run {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	return "Отсканируйте QR-код приложением MeduzaVPN на телефоне, где уже выполнен вход, и подтвердите", nil
}

var reEmail = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

func (m *meduza) loginPassword(email, pass string) (string, error) {
	email = strings.TrimSpace(email)
	if !reEmail.MatchString(email) {
		return "", errors.New("введите адрес почты аккаунта MeduzaVPN")
	}
	if pass == "" {
		return "", errors.New("введите пароль")
	}
	// пароль передаётся только через stdin: в аргументах его видели бы все процессы системы
	out, code := S.Run(60*time.Second, pass+"\n", "meduzavpn", "login", "--email", email, "--password-stdin")
	if code != 0 {
		Decide("WARN", "MeduzaVPN: вход по паролю (%s) не выполнен: %s", email, firstLine(out))
		return "", errors.New("вход не выполнен: " + firstLine(out))
	}
	Decide("INFO", "MeduzaVPN: вход по паролю выполнен (%s)", email)
	m.lmu.Lock()
	m.lg = mdzLogin{Result: "Вход выполнен"}
	m.lmu.Unlock()
	m.loginWork.Add(1)
	go func() { defer m.loginWork.Done(); m.readStatus(); m.catalog(true); m.Tick() }()
	return "Вход выполнен", nil
}

// ---------------------------------------------------------------- подключение и восстановление
func (m *meduza) connect(proto string) bool {
	args := []string{"connect"}
	if s := cfg("meduza.serviceId", ""); s != "" {
		args = append(args, s)
	}
	out, code := m.cli(append(args, "--protocol", proto, "--wait")...)
	Log("INFO", "MeduzaVPN: connect --protocol %s → код %d %s", proto, code, strings.TrimSpace(out))
	return code == 0
}
func (m *meduza) ok() bool { return probe(m.iface, cfg("vpn.probeUrl", "https://1.1.1.1")) }
func inetUp() bool {
	if i := mod("inet"); i != nil {
		return i.Status().Up
	}
	return true
}
func (m *meduza) restart(why string) bool {
	now := time.Now()
	var keep []time.Time
	for _, t := range m.restarts {
		if now.Sub(t) < 30*time.Minute {
			keep = append(keep, t)
		}
	}
	m.restarts = keep
	if len(keep) >= cfgInt("meduza.maxRestartsPer30Min", 5) {
		Decide("ERROR", "MeduzaVPN: служба перезапускалась %d раз за 30 минут → автоперезапуск остановлен (причина: %s), нужен журнал службы", len(keep), why)
		return false
	}
	m.restarts = append(m.restarts, now)
	m.restartN++
	m.lastRst, m.lastRstWhy = now, why
	Decide("WARN", "MeduzaVPN: %s → перезапуск службы meduzavpnd", why)
	run("systemctl", "restart", "meduzavpnd")
	return true
}

func (m *meduza) Tick() {
	m.tk.Lock()
	defer m.tk.Unlock()
	if m.updating {
		m.setSt(1, false, "Обновляется", "идёт установка новой версии MeduzaVPN")
		return
	}
	m.readDaemonCfg()
	m.checkVersion(false)
	if cfg("meduza.enabled", "true") != "true" {
		m.setSt(-1, false, "Выключен", "модуль отключён в настройках")
		return
	}
	if !active("meduzavpnd") {
		m.setSt(2, false, "Служба не работает", "meduzavpnd остановлена")
		if !inetUp() {
			return
		}
		m.restart("служба meduzavpnd не работает")
		return
	}
	if !m.readStatus() {
		m.setSt(2, false, "CLI не отвечает", "meduzavpn status вернул ошибку")
		return
	}
	if !m.signed {
		m.fails = 0
		m.setSt(2, false, "Не выполнен вход", "Войдите по QR-коду или по почте и паролю — кнопки на этой странице")
		return
	}
	m.catalog(false)
	m.lmu.Lock()
	moving := time.Now().Before(m.locationUntil)
	m.lmu.Unlock()
	if moving {
		m.publish(1, false, "Смена локации", "MeduzaVPN переносит VPN, затем шлюз переподключится автоматически")
		return
	}
	if time.Since(m.pingAt) > time.Duration(cfgInt("meduza.pingEveryMin", 30))*time.Minute && len(m.services) > 0 {
		go m.pingAll(false)
	}
	if !m.conn {
		if !inetUp() {
			m.publish(2, false, "Не подключено", "нет интернета у провайдера — подключение отложено")
			return
		}
		Decide("WARN", "MeduzaVPN: туннель не подключён → подключение (%s)", m.proto())
		m.connect(m.proto())
		m.readStatus()
	}
	if m.conn && m.ok() {
		if m.fails > 0 {
			Decide("INFO", "MeduzaVPN: трафик снова проходит (протокол %s)", m.curProto)
		}
		m.fails = 0
		// вернуть выбранный протокол после паузы
		if m.override != "" && time.Since(m.ovAt) > time.Duration(cfgInt("meduza.protocolReturnMin", 30))*time.Minute {
			m.returnProto()
		}
		why, lvl := "", 0
		if m.override != "" {
			lvl, why = 1, "работает запасной протокол "+m.override+" вместо "+cfg("meduza.protocol", "ultra")
		}
		m.publish(lvl, true, "Подключено", why)
		return
	}
	m.fails++
	m.publish(2, false, "Нет трафика", fmt.Sprintf("проверка через %s не проходит (%d подряд)", m.iface, m.fails))
	if !inetUp() {
		if m.fails == 1 {
			Decide("WARN", "MeduzaVPN: нет трафика, но и провайдер не отвечает → восстановление туннеля не запускается")
		}
		return
	}
	m.ladder()
}

// ladder — лестница восстановления: тот же протокол → другие протоколы → служба. Каждая ступень пишет решение.
func (m *meduza) ladder() {
	need := cfgInt("meduza.failChecks", 2)
	switch {
	case m.fails < need:
	case m.fails == need:
		Decide("WARN", "MeduzaVPN: трафик не проходит %d проверки подряд → переподключение тем же протоколом (%s)", m.fails, m.proto())
		m.cli("disconnect")
		m.connect(m.proto())
	case m.fails == need+1 && cfgBool("meduza.autoProtocol", true):
		if m.fallback() {
			return
		}
	default:
		if m.restart("переподключения не помогли") {
			m.override, m.fails = "", need-1
		}
	}
}

// fallback — перебор других протоколов: сначала те, что работали в последнем тесте (по отклику), потом остальные.
// Не чаще раза в 15 минут; без интернета не перебирает; после N неподключившихся подряд считает недоступным сам сервис.
func (m *meduza) fallback() bool {
	if time.Since(m.fbAt) < 15*time.Minute {
		return false
	}
	m.fbAt = time.Now()
	chosen, cur := cfg("meduza.protocol", "ultra"), m.proto()
	skip := map[string]bool{}
	for _, s := range strings.Split(cfg("meduza.protoFallbackSkip", ""), ",") {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			skip[s] = true
		}
	}
	var order []string
	seen := map[string]bool{cur: true}
	tested := append([]mdzTest(nil), m.tests...)
	sort.SliceStable(tested, func(i, j int) bool { return tested[i].Ms < tested[j].Ms })
	for _, t := range tested {
		if t.OK && !seen[t.Proto] && !skip[strings.ToLower(t.Proto)] {
			order, seen[t.Proto] = append(order, t.Proto), true
		}
	}
	for _, p := range append(m.protos, mdzItem{ID: chosen}) {
		if !seen[p.ID] && !skip[strings.ToLower(p.ID)] {
			order, seen[p.ID] = append(order, p.ID), true
		}
	}
	if len(order) == 0 {
		Decide("WARN", "MeduzaVPN: других протоколов нет (список не получен) — пробовать нечего")
		return false
	}
	Decide("WARN", "MeduzaVPN: протокол %s не пропускает трафик → пробую другие: %s", cur, strings.Join(order, ", "))
	noConn, maxNo := 0, max(2, cfgInt("meduza.fallbackMaxTimeouts", 3))
	for _, p := range order {
		if !inetUp() {
			Decide("WARN", "MeduzaVPN: пропал интернет провайдера → перебор протоколов прерван")
			m.connect(m.proto())
			return true
		}
		m.busy("пробую протокол " + p)
		m.cli("disconnect")
		c := m.connect(p)
		if c && m.ok() {
			m.busy("")
			if p == chosen {
				m.override = ""
				Decide("INFO", "MeduzaVPN: снова работает выбранный протокол %s", p)
			} else {
				m.override, m.ovAt = p, time.Now()
				Decide("WARN", "MeduzaVPN: %s не пропускает трафик → найден рабочий протокол %s (временно, выбранный в настройках не меняется)", chosen, p)
			}
			m.fails = 0
			m.readStatus()
			m.publish(map[bool]int{true: 1, false: 0}[m.override != ""], true, "Подключено", map[bool]string{true: "работает запасной протокол " + p + " вместо " + chosen, false: ""}[m.override != ""])
			return true
		}
		if c {
			noConn = 0
		} else {
			noConn++
		}
		if noConn >= maxNo {
			m.busy("")
			Decide("WARN", "MeduzaVPN: %d протокола подряд не подключились, а интернет есть — похоже, недоступен сам сервис MeduzaVPN; перебор прерван, повтор через 15 минут", noConn)
			m.connect(m.proto())
			return false
		}
	}
	m.busy("")
	Decide("ERROR", "MeduzaVPN: ни один протокол не пропускает трафик")
	m.connect(m.proto())
	return false
}
func (m *meduza) returnProto() {
	want := cfg("meduza.protocol", "ultra")
	if m.connect(want) && m.ok() {
		Decide("INFO", "MeduzaVPN: выбранный протокол %s снова работает → возвращён", want)
		m.override = ""
	} else {
		Decide("INFO", "MeduzaVPN: %s по-прежнему не работает → остаюсь на %s", want, m.override)
		m.connect(m.override)
		m.ovAt = time.Now()
	}
}
func (m *meduza) publish(lvl int, up bool, state, why string) {
	m.mu.Lock()
	st := m.st
	m.mu.Unlock()
	svc := cfg("meduza.serviceId", "")
	if n := pickStr(st, "service_name"); n != "" {
		svc = n
	} else if svc == "" {
		svc = "по умолчанию"
	}
	proto := m.curProto
	if m.override != "" {
		proto += " (запасной вместо " + cfg("meduza.protocol", "ultra") + ")"
	}
	kv := [][2]string{{"Аккаунт", orDash(m.account)}, {"VPN", svc}, {"Протокол", proto}, {"Интерфейс", m.iface}}
	if ep := pickStr(st, "endpoint"); ep != "" {
		kv = append(kv, [2]string{"Сервер", ep})
	}
	if s, err := strconv.ParseInt(pickStr(st, "since_unix"), 10, 64); err == nil && s > 0 && m.conn {
		kv = append(kv, [2]string{"Подключено", "с " + time.Unix(s, 0).Format("02.01 15:04")})
	}
	if r := pickStr(st, "date_renews", "renews", "renewal"); r != "" {
		kv = append(kv, [2]string{"Подписка продлевается", r})
	}
	if e := pickStr(st, "last_error"); e != "" {
		kv = append(kv, [2]string{"Последняя ошибка службы", e})
	}
	ver := orDash(m.ver)
	if m.remote != "" && m.remote != m.ver {
		ver += " (доступна " + m.remote + ")"
	}
	kv = append(kv, [2]string{"Версия", ver}, [2]string{"Перезапусков службы", fmt.Sprintf("%d за 30 мин (не больше %d), всего %d", len(m.restarts), cfgInt("meduza.maxRestartsPer30Min", 5), m.restartN)})
	if !m.lastRst.IsZero() {
		kv = append(kv, [2]string{"Последний перезапуск", m.lastRst.Format("02.01 15:04") + " — " + m.lastRstWhy})
	}
	m.setSt(lvl, up, state, why, kv...)
}
func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// ---------------------------------------------------------------- версия и обновление
var reVer = regexp.MustCompile(`\d+\.\d+\.\d+(\+\d+)?`)

func (m *meduza) checkVersion(force bool) {
	if m.ver == "" || force {
		out, _ := m.cli("version")
		m.ver = reVer.FindString(out)
		// The CLI omits the build suffix; dpkg holds the installed package version.
		if version, code := run("dpkg-query", "-W", "-f=${Version}", "meduzavpn"); code == 0 {
			if installed := reVer.FindString(strings.Replace(strings.TrimSpace(version), "-", "+", 1)); installed != "" {
				m.ver = installed
			}
		}
	}
	if !force && time.Since(m.remoteAt) < time.Duration(max(1, cfgInt("meduza.updateCheckHours", 6)))*time.Hour {
		return
	}
	m.remoteAt = time.Now()
	if f := m.releaseFile(); f != nil {
		m.remote = pickStr(f, "version")
		if !routesStarting.Load() && !m.updating && cfgBool("meduza.autoUpdate", false) && m.remote != "" && m.ver != "" && verLess(m.ver, m.remote) {
			go m.update()
		}
	}
}

// releaseFile — описание пакета .deb для этой архитектуры из release.json сервера сборок MeduzaVPN.
func (m *meduza) releaseFile() map[string]any {
	out, code := S.Run(30*time.Second, "", "curl", "-s", "--max-time", "25", cfg("meduza.releaseUrl", "https://meduzavpn-builds.fra1.digitaloceanspaces.com/latest/release.json"))
	if code != 0 {
		return nil
	}
	arch, _ := run("dpkg", "--print-architecture")
	key := "meduzavpn_" + strings.TrimSpace(arch) + ".deb"
	for _, x := range jsonArr(out, "files") {
		if d, ok := x.(map[string]any); ok && pickStr(d, "key") == key {
			return d
		}
	}
	return nil
}
func verLess(a, b string) bool {
	pa, pb := regexp.MustCompile(`\d+`).FindAllString(a, -1), regexp.MustCompile(`\d+`).FindAllString(b, -1)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}

// update — скачать .deb, сверить sha256 из release.json, установить и перезапустить службу.
func (m *meduza) update() (string, error) {
	f := m.releaseFile()
	if f == nil {
		return "", errors.New("в release.json нет пакета для этой системы")
	}
	m.updating = true
	defer func() { m.updating = false }()
	m.busy("обновление MeduzaVPN")
	defer m.busy("")
	deb := "/var/cache/vpnguard/meduzavpn.deb"
	run("mkdir", "-p", "/var/cache/vpnguard")
	if _, code := S.Run(15*time.Minute, "", "curl", "-sfL", "--max-time", "880", "-o", deb, pickStr(f, "versioned_url", "url")); code != 0 {
		return "", errors.New("пакет не скачался")
	}
	sum, _ := run("sha256sum", deb)
	if want := strings.ToLower(pickStr(f, "sha256")); want == "" || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(sum)), want) {
		_ = S.Remove(deb)
		Decide("ERROR", "MeduzaVPN: sha256 скачанного пакета не совпал с release.json → обновление отменено")
		return "", errors.New("контрольная сумма пакета не совпала — обновление отменено")
	}
	if out, code := S.Run(5*time.Minute, "", "dpkg", "-i", deb); code != 0 {
		return "", errors.New("dpkg: " + firstLine(out))
	}
	_ = S.Remove(deb)
	run("systemctl", "restart", "meduzavpnd")
	old := m.ver
	m.checkVersion(true)
	Decide("INFO", "MeduzaVPN: обновлён %s → %s", old, m.ver)
	return "MeduzaVPN обновлён до " + m.ver, nil
}

// ---------------------------------------------------------------- страница
func (m *meduza) Exit() *Exit { return &Exit{Iface: m.iface, Table: 101, Mark: 0x11} }

// настройки самой службы (/etc/meduzavpn/config.json), меняются через meduzavpn config set/unset
var mdzDaemonKeys = []struct{ Key, Title, Type, Help string }{
	{"kill_switch", "Kill switch службы", "tri", "На шлюзе — «нет»: иначе служба блокирует всё мимо своего туннеля, и выходы «Напрямую», AmneziaWG и zapret перестают работать"},
	{"exclude_routes", "Мимо туннеля (раздельное туннелирование)", "list", "Сети через запятую, которые служба не заворачивает в туннель. Домашнюю сеть (например 192.168.1.0/24) внесите сюда"},
	{"routes", "Только эти сети через туннель", "list", "Пусто — решает профиль сервера (обычно весь трафик). Маршрутами клиентов управляет вкладка «Маршруты»"},
	{"dns", "DNS туннеля", "list", "Пусто — DNS из профиля сервера"},
	{"mtu", "MTU туннеля", "text", "Пусто — подбирает служба; иначе 576–9000"},
	{"ipv6", "IPv6 через туннель", "tri", "Пусто — решает профиль"},
	{"auto_connect", "Подключаться при запуске службы", "tri", "Подключение и так держит VpnGuard; «да» поднимает туннель раньше агента"},
}

func (m *meduza) daemonVal(k string) string {
	m.mu.Lock()
	v, ok := m.dcfg[k]
	m.mu.Unlock()
	if !ok || v == nil {
		return ""
	}
	if a, isA := v.([]any); isA {
		var s []string
		for _, x := range a {
			s = append(s, fmt.Sprint(x))
		}
		return strings.Join(s, ", ")
	}
	if f, isF := v.(float64); isF {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}
func (m *meduza) Fields() []Field {
	var sv, pr []Opt
	sv = append(sv, Opt{"", "по умолчанию"})
	for _, s := range m.services {
		t := s.Name
		if s.Info != "" {
			t += " · " + s.Info
		}
		sv = append(sv, Opt{s.ID, t + " · " + m.pingText(s.ID)})
	}
	for _, p := range m.protos {
		t := p.Name
		if p.Info != "" {
			t += " — " + p.Info
		}
		pr = append(pr, Opt{p.ID, t})
	}
	f := []Field{
		fb("meduza.serviceId", "VPN (страна)", "select", "", "Рядом с каждой страной — пинг до её сервера с интерфейса провайдера", sv...),
		fb("meduza.protocol", "Протокол", "select", "ultra", "После смены агент переподключится сам", pr...),
		fb("meduza.enabled", "Модуль включён", "bool", "true", ""),
	}
	for i := range f {
		f[i].Group = "Подключение"
	}
	g := "Восстановление"
	f = append(f,
		Field{Key: "meduza.autoProtocol", Title: "Автоподбор протокола при сбое", Type: "bool", Value: cfg("meduza.autoProtocol", "true"), Help: "Пробует остальные протоколы, если выбранный не пропускает трафик", Group: g},
		Field{Key: "meduza.protoFallbackSkip", Title: "Не пробовать при автоподборе", Type: "text", Value: cfg("meduza.protoFallbackSkip", ""), Help: "Протоколы через запятую, например wireguard", Group: g},
		Field{Key: "meduza.protocolReturnMin", Title: "Возврат к выбранному протоколу, мин", Type: "number", Value: cfg("meduza.protocolReturnMin", "30"), Group: g},
		Field{Key: "meduza.failChecks", Title: "Неудачных проверок до восстановления", Type: "number", Value: cfg("meduza.failChecks", "2"), Group: g},
		Field{Key: "meduza.fallbackMaxTimeouts", Title: "Неподключений подряд до паузы перебора", Type: "number", Value: cfg("meduza.fallbackMaxTimeouts", "3"), Help: "Столько протоколов подряд не подключились — значит, недоступен сам сервис", Group: g},
		Field{Key: "meduza.maxRestartsPer30Min", Title: "Перезапусков службы за 30 минут, не больше", Type: "number", Value: cfg("meduza.maxRestartsPer30Min", "5"), Group: g},
		Field{Key: "meduza.connectTimeoutSec", Title: "Ожидание подключения, с", Type: "number", Value: cfg("meduza.connectTimeoutSec", "90"), Group: g},
		Field{Key: "meduza.pingEveryMin", Title: "Пинг до серверов раз в, мин", Type: "number", Value: cfg("meduza.pingEveryMin", "30"), Group: g},
		Field{Key: "meduza.autoUpdate", Title: "Обновлять MeduzaVPN автоматически", Type: "bool", Value: cfg("meduza.autoUpdate", "false"), Help: "Проверка раз в 6 часов; пакет сверяется по sha256 из release.json", Group: g},
	)
	tri := []Opt{{"", "по умолчанию"}, {"true", "да"}, {"false", "нет"}}
	for _, k := range mdzDaemonKeys {
		fl := Field{Key: "meduza.cfg." + k.Key, Title: k.Title, Type: "text", Value: m.daemonVal(k.Key), Help: k.Help, Group: "Служба MeduzaVPN (" + mdzConfPath + ")"}
		if k.Type == "tri" {
			fl.Type, fl.Options = "select", tri
		}
		f = append(f, fl)
	}
	return f
}

var reCIDRish = regexp.MustCompile(`^[0-9a-fA-F:.]+(/\d{1,3})?$`)

func (m *meduza) Set(k, v string) error {
	if strings.HasPrefix(k, "meduza.cfg.") {
		key := strings.TrimPrefix(k, "meduza.cfg.")
		v = strings.TrimSpace(v)
		args := []string{"config", "unset", key}
		if v != "" {
			var vals []string
			for _, x := range strings.Split(v, ",") {
				if x = strings.TrimSpace(x); x != "" {
					if (key == "exclude_routes" || key == "routes" || key == "dns") && !reCIDRish.MatchString(x) {
						return fmt.Errorf("«%s» — не адрес и не сеть", x)
					}
					vals = append(vals, x)
				}
			}
			if key == "mtu" {
				if n, err := strconv.Atoi(v); err != nil || n < 576 || n > 9000 {
					return errors.New("MTU — число от 576 до 9000 или пусто")
				}
			}
			args = append([]string{"config", "set", key}, vals...)
		}
		if out, code := m.cli(args...); code != 0 {
			return errors.New("meduzavpn config: " + firstLine(out))
		}
		m.readDaemonCfg()
		Decide("INFO", "MeduzaVPN: настройка службы %s = %s (применится при следующем подключении)", key, orDash(v))
		return nil
	}
	setCfg(k, v)
	if k == "meduza.protocol" || k == "meduza.serviceId" {
		m.override = ""
		go func() { m.cli("disconnect"); m.connect(m.proto()); m.Tick() }()
	}
	return nil
}
func (m *meduza) Actions() []Action {
	a := []Action{
		{ID: "reconnect", Title: "Переподключить", Confirm: "Клиенты на этом выходе на несколько секунд потеряют связь. Переподключить?"},
		{ID: "disconnect", Title: "Отключить", Danger: true, Confirm: "Отключить туннель MeduzaVPN? Модуль будет выключен, агент перестанет его подключать."},
	}
	if !m.signed {
		a = append(a, Action{ID: "login", Title: "Войти по QR-коду"},
			Action{ID: "loginpw", Title: "Войти по почте и паролю", Args: []Field{{Key: "email", Title: "Почта аккаунта", Type: "text"}, {Key: "password", Title: "Пароль", Type: "password"}}})
	}
	a = append(a,
		Action{ID: "test", Title: "Тест протоколов", Confirm: "Тест по очереди подключает каждый протокол (до минуты на протокол). Пока он идёт, трафик уходит на резерв. Начать?"},
		Action{ID: "return", Title: "Вернуть выбранный протокол"},
		Action{ID: "refresh", Title: "Обновить список VPN"},
		Action{ID: "ping", Title: "Измерить пинг"},
		Action{ID: "restart", Title: "Перезапустить службу", Danger: true, Confirm: "Перезапустить meduzavpnd? Туннель переподключится."},
		Action{ID: "journal", Title: "Журнал службы"},
		Action{ID: "version", Title: "Проверить обновление"},
	)
	if m.remote != "" && m.ver != "" && verLess(m.ver, m.remote) {
		a = append(a, Action{ID: "update", Title: "Обновить до " + m.remote, Confirm: "Скачать и установить MeduzaVPN " + m.remote + "? Служба перезапустится, туннель переподключится."})
	}
	if m.signed {
		a = append(a, Action{ID: "locations", Title: "Сменить локацию"},
			Action{ID: "revoke-others", Title: "Отключить все устройства, кроме шлюза", Danger: true, Confirm: "Отключить от аккаунта ВСЕ устройства, кроме этого шлюза? На телефонах и ПК придётся войти заново."},
			Action{ID: "logout", Title: "Выйти из аккаунта", Danger: true, Confirm: "Выйти из аккаунта MeduzaVPN на шлюзе? Туннель отключится, пока не будет выполнен вход снова."})
	}
	return a
}
func (m *meduza) Do(id string, a map[string]string) (string, error) {
	switch id {
	case "change-location":
		return m.changeLocation(a)
	case "reconnect":
		m.cli("disconnect")
		if !m.connect(m.proto()) {
			return "", errors.New("подключение не удалось — причина в журнале")
		}
		go m.Tick()
		return "Туннель переподключён", nil
	case "disconnect":
		setCfg("meduza.enabled", "false")
		m.cli("disconnect")
		go m.Tick()
		return "Туннель отключён, модуль выключен", nil
	case "login":
		return m.loginQR()
	case "loginpw":
		return m.loginPassword(a["email"], a["password"])
	case "logout":
		m.cli("disconnect")
		out, code := m.cli("logout")
		if code != 0 {
			return "", errors.New(firstLine(out))
		}
		Decide("WARN", "MeduzaVPN: выполнен выход из аккаунта (из веб-интерфейса)")
		go m.Tick()
		return "Выход выполнен", nil
	case "return":
		if m.override == "" {
			return "Уже работает выбранный протокол", nil
		}
		m.returnProto()
		return "Проверен возврат к выбранному протоколу", nil
	case "restart":
		run("systemctl", "restart", "meduzavpnd")
		go m.Tick()
		return "Служба перезапущена", nil
	case "refresh":
		m.catalog(true)
		if m.catErr != "" {
			return "", errors.New(m.catErr)
		}
		return fmt.Sprintf("VPN: %d, протоколов: %d. Пинг измеряется", len(m.services), len(m.protos)), nil
	case "ping":
		go m.pingAll(a["row"] != "")
		return "Пинг измеряется, результаты появятся в списке VPN", nil
	case "journal":
		out, _ := run("journalctl", "-u", "meduzavpnd", "-n", "60", "--no-pager")
		m.out, m.outTitle = out, "Журнал службы meduzavpnd"
		return "Журнал показан на странице", nil
	case "version":
		m.checkVersion(true)
		if m.remote == "" {
			return "", errors.New("не удалось получить release.json сервера сборок")
		}
		if verLess(m.ver, m.remote) {
			return "Доступна версия " + m.remote + " (установлена " + orDash(m.ver) + ")", nil
		}
		return "Установлена актуальная версия " + orDash(m.ver), nil
	case "update":
		return m.update()
	case "revoke":
		if a["row"] == "" {
			return "", errors.New("устройство не выбрано")
		}
		for _, d := range m.devices {
			if d[0] == a["row"] && d[7] != "" {
				return "", errors.New("это сам шлюз — для него используйте «Выйти из аккаунта»")
			}
		}
		if out, code := m.cli("devices", "revoke", a["row"]); code != 0 {
			return "", errors.New(firstLine(out))
		}
		m.readDevices()
		return "Устройство отключено от аккаунта", nil
	case "revoke-others":
		if out, code := m.cli("devices", "revoke-others"); code != 0 {
			return "", errors.New(firstLine(out))
		}
		m.readDevices()
		Decide("WARN", "MeduzaVPN: все остальные устройства отключены от аккаунта (из веб-интерфейса)")
		return "Остальные устройства отключены", nil
	case "test":
		go m.protoTest()
		return "Тест запущен, результаты появятся в таблице", nil
	}
	return "", errors.New("неизвестное действие")
}
func (m *meduza) protoTest() {
	if !m.tk.TryLock() {
		return
	}
	defer m.tk.Unlock()
	m.catalog(true)
	protos := m.protos
	if len(protos) == 0 {
		protos = []mdzItem{{ID: cfg("meduza.protocol", "ultra"), Name: cfg("meduza.protocol", "ultra")}}
	}
	var res []mdzTest
	for i, p := range protos {
		m.busy(fmt.Sprintf("тест протокола %s (%d из %d)", p.Name, i+1, len(protos)))
		m.cli("disconnect")
		t := time.Now()
		args := []string{"connect"}
		if s := cfg("meduza.serviceId", ""); s != "" {
			args = append(args, s)
		}
		out, code := m.cli(append(args, "--protocol", p.ID, "--wait")...)
		r := mdzTest{Proto: p.ID, Name: p.Name, ConnSec: time.Since(t).Seconds(), Ms: -1}
		if code == 0 {
			m.readStatus()
			r.OK, r.Ms = probeMs(m.iface, cfg("vpn.probeUrl", "https://1.1.1.1"))
			r.Result = map[bool]string{true: "трафик проходит", false: "подключился, трафика нет"}[r.OK]
		} else {
			r.Result, r.Err = "не подключился", firstLine(out)
		}
		Log("INFO", "MeduzaVPN: тест %s: %s, подключение %.1f с, отклик %d мс %s", p.ID, r.Result, r.ConnSec, r.Ms, r.Err)
		res = append(res, r)
		m.tests = append([]mdzTest(nil), res...)
	}
	m.testAt = time.Now().Format("02.01 15:04")
	m.busy("возвращаю протокол " + m.proto())
	m.cli("disconnect")
	m.connect(m.proto())
	m.readStatus()
	m.busy("")
	var good []string
	for _, r := range res {
		if r.OK {
			good = append(good, fmt.Sprintf("%s (%d мс)", r.Proto, r.Ms))
		}
	}
	Decide("INFO", "MeduzaVPN: тест протоколов завершён, работают: %s; возвращён %s", orDash(strings.Join(good, ", ")), m.proto())
}
func (m *meduza) Tables() []Table {
	var t []Table
	m.lmu.Lock()
	lg := m.lg
	m.lmu.Unlock()
	switch {
	case lg.Running && lg.URL != "":
		left := time.Until(lg.Until).Round(time.Second)
		note := "Откройте приложение MeduzaVPN на телефоне, где уже выполнен вход, отсканируйте код и подтвердите вход. Сам код ничего не подтверждает — вход завершит только агент на шлюзе."
		txt := "Ссылка: " + lg.URL
		if lg.Code != "" {
			txt = "Код: " + lg.Code + "\n" + txt
		}
		if left > 0 {
			txt += fmt.Sprintf("\nКод действует ещё %d мин %02d с", int(left.Minutes()), int(left.Seconds())%60)
		}
		t = append(t, Table{Title: "Вход по QR-коду", Img: qrImage(lg.URL), Note: note, Text: txt, Top: true})
	case lg.Running:
		t = append(t, Table{Title: "Вход по QR-коду", Text: "Запрашиваю код у сервера MeduzaVPN…", Top: true})
	case lg.Result != "" && !m.signed:
		t = append(t, Table{Title: "Вход", Text: lg.Result, Top: true})
	}
	var sv [][]string
	cur := cfg("meduza.serviceId", "")
	for _, s := range m.services {
		mark := ""
		if s.ID == cur {
			mark = "выбран"
		}
		m.pmu.Lock()
		host := m.pings[s.ID].Host
		m.pmu.Unlock()
		sv = append(sv, []string{s.ID, s.Name, s.Info, m.pingText(s.ID), orDash(host), mark})
	}
	empty := "Список пуст — выполните вход"
	if m.catErr != "" {
		empty = "Список не получен: " + m.catErr
	}
	t = append(t, Table{Title: "VPN на аккаунте", Cols: []string{"id", "Название", "Сведения", "Пинг", "Сервер", ""}, Rows: sv, Empty: empty,
		Note:    "Пинг — с интерфейса провайдера в обход туннелей: ICMP, а если сервер его не пропускает — время TCP-соединения. Адрес сервера берётся из профиля подключения (meduzavpn profile).",
		Actions: []Action{{ID: "ping", Title: "Пинг заново (с поиском адреса)"}}})
	var tr [][]string
	for _, r := range m.tests {
		ms := "—"
		if r.Ms >= 0 {
			ms = fmt.Sprintf("%d мс", r.Ms)
		}
		name := r.Name
		if r.Proto == cfg("meduza.protocol", "ultra") {
			name += " (выбран)"
		}
		tr = append(tr, []string{r.Proto, name, r.Result, fmt.Sprintf("%.1f с", r.ConnSec), ms, r.Err})
	}
	tn := ""
	if m.testAt != "" {
		tn = "Последний тест: " + m.testAt + ". Автоподбор при сбое сначала пробует рабочие протоколы с меньшим откликом."
	}
	t = append(t, Table{Title: "Тест протоколов", Cols: []string{"id", "Протокол", "Результат", "Подключение", "Отклик", "Ошибка"}, Rows: tr, Empty: "Тест ещё не запускался", Note: tn})
	if m.signed {
		m.mu.Lock()
		dv := m.devices
		m.mu.Unlock()
		t = append(t, Table{Title: "Устройства на аккаунте", Cols: []string{"id", "Устройство", "Платформа", "Версия", "Адрес", "Вход", "Активность", ""}, Rows: dv,
			Empty: "Список устройств не получен", Note: "Устройства, вошедшие в этот аккаунт MeduzaVPN. Незнакомое — отключите; кнопка «Отключить все устройства, кроме шлюза» — в управлении.",
			Actions: []Action{{ID: "revoke", Title: "Отключить", Danger: true, Confirm: "Отключить это устройство от аккаунта MeduzaVPN?"}}})
	}
	if m.out != "" {
		t = append(t, Table{Title: m.outTitle, Text: m.out})
	}
	return t
}
func (m *meduza) Checks() []Check {
	return []Check{
		{ID: "meduza.daemon", Title: "Служба meduzavpnd работает", FixTitle: "Перезапустить службу",
			Run: func() Finding {
				return Finding{OK: active("meduzavpnd"), Text: "systemctl is-active meduzavpnd", Hint: "Смотрите журнал службы: кнопка «Журнал службы» на вкладке MeduzaVPN"}
			},
			Fix: func() (string, error) {
				run("systemctl", "restart", "meduzavpnd")
				return "служба перезапущена", nil
			}},
		{ID: "meduza.signin", Title: "Выполнен вход в аккаунт",
			Run: func() Finding {
				m.readStatus()
				return Finding{OK: m.signed, Text: "meduzavpn status · " + orDash(m.account), Hint: "Автоматически не чинится: войдите по QR-коду или по почте на вкладке MeduzaVPN. Если вход слетает снова — проверьте подписку и список устройств"}
			}},
		{ID: "meduza.killswitch", Title: "Kill switch службы не мешает другим выходам", FixTitle: "Выключить kill switch",
			Run: func() Finding {
				m.readDaemonCfg()
				return Finding{OK: m.daemonVal("kill_switch") == "false", Text: "kill_switch = " + orDash(m.daemonVal("kill_switch")),
					Hint: "Со включённым kill switch служба блокирует трафик мимо своего туннеля: «Напрямую», AmneziaWG и zapret не работают. По умолчанию он может быть включён"}
			},
			Fix: func() (string, error) {
				return "kill switch выключен", m.Set("meduza.cfg.kill_switch", "false")
			}},
		{ID: "meduza.connected", Title: "Туннель подключён", FixTitle: "Подключить",
			Run: func() Finding {
				m.readStatus()
				return Finding{OK: m.conn, Text: "протокол " + orDash(m.curProto)}
			},
			Fix: func() (string, error) { m.connect(m.proto()); return "выполнено подключение", nil }},
		{ID: "meduza.iface", Title: "Интерфейс туннеля существует",
			Run: func() Finding {
				_, c := run("ip", "-o", "link", "show", m.iface)
				return Finding{OK: c == 0, Text: m.iface, Hint: "Служба подключена, но интерфейса нет — перезапустите службу"}
			}},
		{ID: "meduza.traffic", Title: "Трафик проходит через туннель", FixTitle: "Запустить восстановление",
			Run: func() Finding {
				return Finding{OK: m.ok(), Text: "HTTPS-запрос через " + m.iface, Hint: "Сервер VPN недоступен или протокол блокируется провайдером — поможет другой протокол или другая страна (смотрите пинг)"}
			},
			Fix: func() (string, error) {
				m.fbAt = time.Time{}
				m.fails = cfgInt("meduza.failChecks", 2)
				m.ladder()
				m.fails++
				m.ladder()
				return "пройдены ступени восстановления, см. журнал решений", nil
			}},
		{ID: "meduza.version", Title: "Установлена актуальная версия MeduzaVPN", FixTitle: "Обновить",
			Run: func() Finding {
				return Finding{OK: m.remote == "" || m.ver == "" || !verLess(m.ver, m.remote), Text: "установлена " + orDash(m.ver) + ", на сервере сборок " + orDash(m.remote)}
			},
			Fix: func() (string, error) { return m.update() }},
	}
}
func (m *meduza) Metrics() map[string]float64 {
	out := m.base.Metrics()
	if m.Status().Up {
		out["up"] = 1
	}
	return out
}
