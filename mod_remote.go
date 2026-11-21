// Удалённая диагностика — как в Windows-версии: включается на время с вкладки «Диагностика», доступ по токену
// в заголовке X-Token, адреса те же (/status /check /diag /net /system /files /logs /decisions /bundle /cmd),
// поэтому клиент RemoteDiag.ps1 из Windows-версии работает и с Linux-шлюзом без изменений.
// Токен даёт только чтение; команды (/cmd) — если разрешены отдельно, и только безопасные: без подтверждения «опасно»
// и без ввода данных. Ключи, пароли и QR-коды в ответах скрыты.
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type remoteReq struct{ T, From, Path string }
type remoteMod struct {
	base
	rmu  sync.Mutex
	reqs []remoteReq
	n    int
}

var (
	remMod     = &remoteMod{}
	listenAddr = "127.0.0.1:8765" // задаётся при запуске веб-сервера
)

func init()                                { Register(remMod) }
func (m *remoteMod) ID() string            { return "remote" }
func (m *remoteMod) Name() string          { return "Удалённая диагностика" }
func (m *remoteMod) Color() string         { return "#9fb3c8" }
func (m *remoteMod) Order() int            { return 90 }
func (m *remoteMod) Period() time.Duration { return 20 * time.Second }
func (m *remoteMod) NoPage() bool          { return true }
func (m *remoteMod) Aux() bool             { return true }

func remoteUntil() time.Time {
	t, _ := time.Parse(time.RFC3339, cfg("remote.until", ""))
	return t
}
func remoteOn() bool {
	return cfgBool("remote.enabled", false) && len(cfg("remote.token", "")) >= 16 && time.Now().Before(remoteUntil())
}
func newToken() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// lanAddr — адрес шлюза в домашней сети и порт веб-сервера: их нужно сообщить тому, кто будет подключаться.
func lanAddr() string {
	host, port, _ := net.SplitHostPort(listenAddr)
	if host == "" || host == "0.0.0.0" || host == "::" {
		out, _ := run("ip", "-4", "-o", "addr", "show", "dev", wanIface())
		if x := regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+)/`).FindStringSubmatch(out); x != nil {
			host = x[1]
		} else {
			host = "АДРЕС_ШЛЮЗА"
		}
	}
	return net.JoinHostPort(host, port)
}
func (m *remoteMod) Tick() {
	m.tk.Lock()
	defer m.tk.Unlock()
	m.tickLocked()
}

func (m *remoteMod) tickLocked() {
	if cfgBool("remote.enabled", false) && !time.Now().Before(remoteUntil()) {
		if err := setCfg("remote.enabled", "false"); err != nil {
			Log("ERROR", "Удалённая диагностика: ошибка сохранения истёкшего срока: %v", err)
		} else {
			Decide("INFO", "Удалённая диагностика: время вышло → выключена")
		}
	}
	if !remoteOn() {
		m.setSt(-1, false, "Выключена", "Включите, чтобы разработчик мог получить отчёты с этого шлюза по токену")
		return
	}
	h, _, _ := net.SplitHostPort(listenAddr)
	why := ""
	if h == "127.0.0.1" || h == "localhost" || h == "::1" {
		why = "веб-сервер слушает только " + listenAddr + " — из сети диагностика недоступна (запуск с --listen 0.0.0.0:8765)"
	}
	m.rmu.Lock()
	n, last := m.n, "—"
	if len(m.reqs) > 0 {
		r := m.reqs[len(m.reqs)-1]
		last = r.T + " · " + r.From + " · " + r.Path
	}
	m.rmu.Unlock()
	from := map[string]string{"local": "только домашняя сеть и клиенты WG-Server", "any": "откуда угодно (нужен проброс порта на роутере)"}[cfg("remote.allowFrom", "local")]
	m.setSt(map[bool]int{true: 1, false: 0}[why != ""], true, "Включена до "+remoteUntil().Local().Format("02.01 15:04"), why,
		[2]string{"Адрес", "http://" + lanAddr()}, [2]string{"Откуда", from},
		[2]string{"Команды", map[bool]string{true: "разрешены (только безопасные)", false: "запрещены — только чтение"}[cfgBool("remote.allowActions", false)]},
		[2]string{"Запросов", strconv.Itoa(n)}, [2]string{"Последний", last})
}
func (m *remoteMod) Fields() []Field {
	return []Field{
		{Key: "remote.hours", Title: "Включать на", Type: "select", Value: cfg("remote.hours", "24"), Options: []Opt{{"1", "1 час"}, {"4", "4 часа"}, {"24", "сутки"}, {"72", "3 дня"}, {"168", "неделю"}}},
		{Key: "remote.allowFrom", Title: "Откуда можно подключаться", Type: "select", Value: cfg("remote.allowFrom", "local"), Options: []Opt{{"local", "домашняя сеть и клиенты WG-Server"}, {"any", "откуда угодно"}},
			Help: "«Откуда угодно» нужно, если разработчик подключается из интернета: тогда пробросьте порт на роутере"},
		{Key: "remote.allowActions", Title: "Разрешить команды", Type: "bool", Value: cfg("remote.allowActions", "false"),
			Help: "Переподключить, перезапустить службу, исправить найденную проблему. Опасные действия (выход, смена ключей) не доступны никогда"},
	}
}
func (m *remoteMod) Set(k, v string) error {
	if k == "remote.hours" {
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 168 {
			return errors.New("срок — от 1 до 168 часов")
		}
	}
	if err := setCfg(k, v); err != nil {
		return err
	}
	go m.Tick()
	return nil
}
func (m *remoteMod) Actions() []Action {
	if !remoteOn() {
		return []Action{{ID: "enable", Title: "Включить удалённую диагностику", Confirm: "Включить доступ к отчётам этого шлюза по токену? Через выбранный срок он выключится сам."}}
	}
	return []Action{{ID: "enable", Title: "Продлить"}, {ID: "newtoken", Title: "Новый токен", Confirm: "Старый токен перестанет работать. Создать новый?"},
		{ID: "disable", Title: "Выключить", Danger: true}}
}
func (m *remoteMod) Do(id string, _ map[string]string) (string, error) {
	m.tk.Lock()
	defer m.tk.Unlock()
	switch id {
	case "enable":
		until := time.Now().Add(time.Duration(cfgInt("remote.hours", 24)) * time.Hour)
		values := map[string]string{"remote.until": until.Format(time.RFC3339), "remote.enabled": "true"}
		if !remoteOn() {
			values["remote.token"] = newToken()
		}
		if err := setConfigValues(values); err != nil {
			return "", err
		}
		Decide("WARN", "Удалённая диагностика включена до %s", until.Format("02.01 15:04"))
	case "newtoken":
		if err := setCfg("remote.token", newToken()); err != nil {
			return "", err
		}
		Decide("INFO", "Удалённая диагностика: создан новый токен, прежний не действует")
	case "disable":
		if err := setCfg("remote.enabled", "false"); err != nil {
			return "", err
		}
		Decide("INFO", "Удалённая диагностика выключена")
	default:
		return "", errors.New("неизвестное действие")
	}
	m.tickLocked()
	return map[string]string{"enable": "Удалённая диагностика включена до " + remoteUntil().Local().Format("02.01 15:04"), "newtoken": "Создан новый токен", "disable": "Удалённая диагностика выключена"}[id], nil
}
func (m *remoteMod) Tables() []Table {
	if !remoteOn() {
		return nil
	}
	a, tok := lanAddr(), cfg("remote.token", "")
	text := fmt.Sprintf("VpnGuard для Linux — удалённая диагностика\nАдрес: http://%s\nТокен: %s\nДействует до: %s\n\nWindows (из папки VpnGuard):\n  .\\RemoteDiag.ps1 -Address %s -Token %s\n\nЛюбая система:\n  curl -H \"X-Token: %s\" http://%s/bundle\n",
		a, tok, remoteUntil().Local().Format("02.01.2006 15:04"), a, tok, tok, a)
	t := []Table{{Title: "Данные для подключения", Text: text, File: "vpnguard-remote.txt",
		Note: "Передайте их тому, кто будет смотреть отчёты. Токен открывает только чтение отчётов (и безопасные команды, если они разрешены); веб-интерфейс по нему не открывается."}}
	m.rmu.Lock()
	var rows [][]string
	for i := len(m.reqs) - 1; i >= 0 && len(rows) < 15; i-- {
		r := m.reqs[i]
		rows = append(rows, []string{r.T, r.From, r.Path})
	}
	m.rmu.Unlock()
	return append(t, Table{Title: "Последние запросы", Cols: []string{"Когда", "Откуда", "Что"}, Rows: rows, Empty: "Запросов ещё не было"})
}

// ---------------------------------------------------------------- сервер
var (
	reSecretKV  = regexp.MustCompile(`(?i)((?:PrivateKey|PresharedKey)\s*=\s*)[A-Za-z0-9+/=]{20,}`)
	reSecretJS  = regexp.MustCompile(`(?i)("(?:web\.token|remote\.token|priv|psk|password|token|access_token|refresh_token)"\s*:\s*)"[^"]*"`)
	reImageData = regexp.MustCompile(`data:image/[a-z+.-]+;base64,[A-Za-z0-9+/=]+`)
)

// hideSecrets — убрать из отчёта ключи WireGuard, токены и картинки (в QR-кодах зашиты ключи клиентов).
func hideSecrets(s string) string {
	s = reSecretKV.ReplaceAllString(s, "${1}(скрыт)")
	s = reSecretJS.ReplaceAllString(s, `${1}"(скрыт)"`)
	for _, k := range []string{"remote.token", "web.token"} { // токены — где бы ни встретились (данные для подключения, команды curl)
		if t := cfg(k, ""); len(t) >= 6 {
			s = strings.ReplaceAll(s, t, "(скрыт)")
		}
	}
	return reImageData.ReplaceAllString(s, "(картинка скрыта)")
}

var remotePaths = []string{"/", "/status", "/check", "/diag", "/decisions", "/net", "/system", "/files", "/logs", "/bundle", "/cmd", "/v1/diagnostics/snapshot", "/v1/diagnostics/explanation", "/v1/diagnostics/events", "/v1/diagnostics/telemetry", "/v1/diagnostics/flows", "/v1/diagnostics/flow-lifecycle", "/v1/diagnostics/link-quality"}

func clientIP(r *http.Request) net.IP {
	h, _, _ := net.SplitHostPort(r.RemoteAddr)
	return net.ParseIP(h)
}

// remoteAllowed — включено ли, верный ли токен, разрешён ли адрес. Код ответа и причина — для отказа.
func remoteAllowed(r *http.Request) (int, string) {
	if !remoteOn() {
		return http.StatusForbidden, "удалённая диагностика выключена — включите её на вкладке «Диагностика»"
	}
	tok := cfg("remote.token", "")
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Token")), []byte(tok)) != 1 {
		time.Sleep(time.Second) // перебор токена — медленно
		return http.StatusUnauthorized, "неверный токен"
	}
	if ip := clientIP(r); cfg("remote.allowFrom", "local") != "any" && (ip == nil || !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())) {
		return http.StatusForbidden, "подключение разрешено только из домашней сети"
	}
	return 0, ""
}
func remoteServe(w http.ResponseWriter, r *http.Request) {
	if code, why := remoteAllowed(r); code != 0 {
		http.Error(w, why, code)
		return
	}
	path := r.URL.Path
	q := r.URL.Query()
	from := fmt.Sprint(clientIP(r))
	remMod.rmu.Lock()
	remMod.n++
	desc := path
	if c := q.Get("c"); c != "" {
		desc += " (" + c + ")"
	}
	remMod.reqs = append(remMod.reqs, remoteReq{time.Now().Format("02.01 15:04:05"), from, desc})
	if len(remMod.reqs) > 100 {
		remMod.reqs = remMod.reqs[len(remMod.reqs)-100:]
	}
	remMod.rmu.Unlock()
	if path != "/status" && path != "/v1/diagnostics/events" && path != "/v1/diagnostics/telemetry" && path != "/v1/diagnostics/flows" && path != "/v1/diagnostics/flow-lifecycle" && path != "/v1/diagnostics/link-quality" {
		Log("INFO", "Удалённая диагностика: %s запросил %s", from, desc)
	}
	w.Header().Set("Cache-Control", "no-store")
	text := func(s string) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(hideSecrets(s)))
	}
	qi := func(k string, def int) int {
		if n, err := strconv.Atoi(q.Get(k)); err == nil && n >= 0 {
			return n
		}
		return def
	}
	switch path {
	case "/":
		text(remoteIndex())
	case "/v1/diagnostics/events":
		serveDiagnosticEvents(w, r)
	case "/v1/diagnostics/snapshot", "/v1/diagnostics/explanation", "/v1/diagnostics/telemetry", "/v1/diagnostics/flows", "/v1/diagnostics/flow-lifecycle", "/v1/diagnostics/link-quality":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "требуется GET", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if path == "/v1/diagnostics/link-quality" {
			_ = json.NewEncoder(w).Encode(diagnosticQualityWindow())
			return
		}
		if path == "/v1/diagnostics/flow-lifecycle" {
			_ = json.NewEncoder(w).Encode(struct {
				SchemaVersion int               `json:"schemaVersion"`
				Observation   *lifecycleSummary `json:"observation"`
			}{1, flowsMod.lifecycle()})
			return
		}
		if path == "/v1/diagnostics/flows" {
			_ = json.NewEncoder(w).Encode(struct {
				SchemaVersion int         `json:"schemaVersion"`
				Snapshot      *flowCounts `json:"snapshot"`
			}{1, flowsMod.snapshotCounts()})
			return
		}
		if path == "/v1/diagnostics/telemetry" {
			_ = json.NewEncoder(w).Encode(telemetry.diagnosticWindow(time.Now().Unix()))
			return
		}
		snapshot := readDiagnosticSnapshotV1()
		if path == "/v1/diagnostics/explanation" {
			_ = json.NewEncoder(w).Encode(explainDiagnosticSnapshot(snapshot))
		} else {
			_ = json.NewEncoder(w).Encode(snapshot)
		}
	case "/status":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		b, _ := json.MarshalIndent(buildState(), "", " ")
		_, _ = w.Write([]byte(hideSecrets(string(b))))
	case "/check", "/diag":
		s := reportChecks()
		if path == "/diag" {
			s += "\n" + reportDecisions()
		}
		text(s)
	case "/decisions":
		text(reportDecisions())
	case "/net":
		text(reportNet())
	case "/system":
		text(reportSystem())
	case "/files":
		text(reportFiles())
	case "/logs":
		text(reportLogs(qi("days", 2), qi("minutes", 0), qi("lines", 5000)))
	case "/bundle":
		text(remoteIndex() + "\n" + reportChecks() + "\n" + reportDecisions() + "\n" + reportNet() + "\n" + reportSystem() + "\n" + reportFiles() + "\n" + reportLogs(1, 0, 3000))
	case "/cmd":
		msg, err := remoteCmd(q.Get("c"), from)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		text(msg + "\n")
	default:
		http.NotFound(w, r)
	}
}
func remoteIndex() string {
	return fmt.Sprintf(`VpnGuard для Linux %s — удалённая диагностика
Время шлюза: %s · включена до %s · команды: %s

/v1/diagnostics/link-quality   потери ICMP и задержка за последние пять минут
/v1/diagnostics/flow-lifecycle   события соединений с начала текущей подписки
/v1/diagnostics/flows   число TCP- и UDP-соединений в последнем снимке IPv4
/v1/diagnostics/telemetry   история DNS и состояния MeduzaVPN за пять минут
/v1/diagnostics/events   изменения после cursor или снимок для восстановления
/v1/diagnostics/explanation   объяснение состояния по снимку (JSON, схема 1)
/v1/diagnostics/snapshot   обезличенный снимок модулей и счётчиков решений (JSON, схема 1)
/status      состояние всех модулей (JSON)
/check       проверки диагностики (выполняются заново)
/diag        проверки и журнал решений
/decisions   журнал решений
/net         адреса, маршруты, правила, nftables, туннели
/system      система, службы, журналы служб
/files       настройки и файлы VpnGuard (секреты скрыты)
/logs        журнал агента: ?days=2 ?minutes=30 ?lines=5000
/bundle      всё сразу одним текстом
/cmd?c=…     команда: модуль.действие (например meduza.reconnect), fix:проверка, diagrun
             доступные команды: %s
`, Version, time.Now().Format("02.01.2006 15:04:05"), remoteUntil().Local().Format("02.01 15:04"),
		map[bool]string{true: "разрешены", false: "запрещены"}[cfgBool("remote.allowActions", false)], strings.Join(remoteCmds(), ", "))
}
func section(title, body string) string {
	if strings.TrimSpace(body) == "" {
		body = "(пусто)\n"
	}
	return "==================== " + title + "\n" + strings.TrimRight(body, "\n") + "\n\n"
}
func reportChecks() string {
	var b strings.Builder
	for _, c := range runChecks() {
		mark := "OK "
		if !c.OK {
			mark = "!! "
		}
		fmt.Fprintf(&b, "%s %-14s %s — %s", mark, c.Module, c.Title, c.Text)
		if !c.OK && c.Hint != "" {
			fmt.Fprintf(&b, "\n      что делать: %s", c.Hint)
		}
		if c.FixTitle != "" {
			fmt.Fprintf(&b, "\n      исправить: /cmd?c=fix:%s (%s)", c.ID, c.FixTitle)
		}
		b.WriteString("\n")
	}
	var st strings.Builder
	for _, m := range Mods {
		s := m.Status()
		fmt.Fprintf(&st, "%-22s уровень %2d · %s", m.Name(), s.Level, s.State)
		if s.Why != "" {
			st.WriteString(" · " + s.Why)
		}
		if s.Busy != "" {
			st.WriteString(" · выполняется: " + s.Busy)
		}
		st.WriteString("\n")
		for _, kv := range s.KV {
			fmt.Fprintf(&st, "    %s: %s\n", kv[0], kv[1])
		}
	}
	return section("Модули", st.String()) + section("Проверки", b.String())
}
func reportDecisions() string {
	var b strings.Builder
	for _, l := range snapshotLog(&decRing) {
		fmt.Fprintf(&b, "%s [%s] %s\n", l.T, l.Lvl, l.Text)
	}
	return section("Журнал решений", b.String())
}
func cmdOut(name string, a ...string) string {
	out, code := S.Run(15*time.Second, "", name, a...)
	s := "$ " + name + " " + strings.Join(a, " ") + "\n" + strings.TrimRight(out, "\n")
	if code != 0 {
		s += fmt.Sprintf("\n(код выхода %d)", code)
	}
	return s + "\n\n"
}
func reportNet() string {
	var b strings.Builder
	for _, c := range [][]string{{"ip", "-br", "addr"}, {"ip", "route"}, {"ip", "rule"}, {"ip", "route", "show", "table", "all"},
		{"wg", "show"}, {"awg", "show"}, {"nft", "list", "ruleset"}, {"ss", "-lntup"}, {"resolvectl", "status"},
		{"sysctl", "net.ipv4.ip_forward", "net.ipv4.conf.all.rp_filter"}} {
		b.WriteString(cmdOut(c[0], c[1:]...))
	}
	s, ip := Compile()
	b.WriteString("# Сценарий nftables, который собирает VpnGuard сейчас:\n" + s + "\n# Команды ip:\n")
	for _, x := range ip {
		b.WriteString("ip " + strings.Join(x, " ") + "\n")
	}
	return section("Сеть", b.String())
}
func reportSystem() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("VpnGuard %s · имитация: %v · данные: %s · веб: %s\n\n", Version, Sim, DataDir, listenAddr))
	for _, c := range [][]string{{"uname", "-a"}, {"cat", "/etc/os-release"}, {"uptime"}, {"df", "-h", "/"}, {"free", "-m"}, {"timedatectl"},
		{"systemctl", "--failed", "--no-pager"},
		{"systemctl", "status", "--no-pager", "-n", "0", "vpnguard", "meduzavpnd", wgMod.unit(), "vpnguard-nfqws2"},
		{"meduzavpn", "version"}, {"meduzavpn", "status"},
		{"journalctl", "-u", "meduzavpnd", "-n", "150", "--no-pager"},
		{"journalctl", "-u", wgMod.unit(), "-n", "50", "--no-pager"},
		{"journalctl", "-u", "vpnguard-nfqws2", "-n", "50", "--no-pager"},
		{"journalctl", "-k", "-n", "80", "--no-pager"}} {
		b.WriteString(cmdOut(c[0], c[1:]...))
	}
	return section("Система", b.String())
}
func reportFiles() string {
	var b strings.Builder
	for _, n := range []string{"config.json", "routes.json", "meduza-ping.json"} {
		t, err := os.ReadFile(filepath.Join(DataDir, n))
		if err == nil {
			fmt.Fprintf(&b, "---- %s\n%s\n\n", n, t)
		}
	}
	// клиенты WG-Server — без ключей
	var cl []string
	for _, c := range wgMod.Clients() {
		cl = append(cl, fmt.Sprintf("%s  %-20s off=%v  на связи=%v  %s", c.IP, c.Name, c.Off, c.On, c.Seen))
	}
	fmt.Fprintf(&b, "---- клиенты WG-Server\n%s\n\n", strings.Join(cl, "\n"))
	for _, p := range []string{wgMod.confPath(), mdzConfPath, "/etc/vpnguard/nfqws2.args"} {
		if t, err := S.ReadFile(p); err == nil {
			fmt.Fprintf(&b, "---- %s\n%s\n\n", p, t)
		}
	}
	for _, n := range wgMod.backupFiles() {
		fmt.Fprintf(&b, "резервная копия WG-Server: %s\n", n)
	}
	return section("Файлы", b.String())
}
func reportLogs(days, minutes, lines int) string {
	dir := filepath.Join(DataDir, "logs")
	es, _ := os.ReadDir(dir)
	var files []string
	for _, e := range es {
		if strings.HasPrefix(e.Name(), "vpnguard-") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	if days < 1 {
		days = 1
	}
	if len(files) > days {
		files = files[len(files)-days:]
	}
	since := ""
	if minutes > 0 {
		since = time.Now().Add(-time.Duration(minutes) * time.Minute).Format("2006-01-02 15:04:05")
	}
	var all []string
	for _, f := range files {
		t, _ := os.ReadFile(filepath.Join(dir, f))
		for _, l := range strings.Split(strings.TrimRight(string(t), "\n"), "\n") {
			if l != "" && (since == "" || l >= since) {
				all = append(all, l)
			}
		}
	}
	if lines > 0 && len(all) > lines {
		all = all[len(all)-lines:]
	}
	return section(fmt.Sprintf("Журнал агента (%s)", strings.Join(files, ", ")), strings.Join(all, "\n"))
}

// remoteCmds — команды, доступные удалённо: действия модулей без ввода данных и без пометки «опасно».
func remoteCmds() []string {
	out := []string{"diagrun"}
	for _, m := range Mods {
		if m.ID() == "remote" {
			continue
		}
		for _, a := range m.Actions() {
			if !a.Danger && len(a.Args) == 0 {
				out = append(out, m.ID()+"."+a.ID)
			}
		}
	}
	return out
}
func remoteCmd(c, from string) (string, error) {
	if !cfgBool("remote.allowActions", false) {
		return "", errors.New("команды запрещены: разрешите их на вкладке «Диагностика» шлюза")
	}
	switch {
	case c == "diagrun":
		return reportChecks(), nil
	case strings.HasPrefix(c, "fix:"):
		Decide("WARN", "Удалённая диагностика (%s): исправление %s", from, strings.TrimPrefix(c, "fix:"))
		return fixCheck(strings.TrimPrefix(c, "fix:"))
	}
	for _, x := range remoteCmds() {
		if x == c {
			id, act, _ := strings.Cut(c, ".")
			Decide("WARN", "Удалённая диагностика (%s): команда %s", from, c)
			return mod(id).Do(act, map[string]string{})
		}
	}
	return "", fmt.Errorf("команда %q недоступна; доступные: %s", c, strings.Join(remoteCmds(), ", "))
}
