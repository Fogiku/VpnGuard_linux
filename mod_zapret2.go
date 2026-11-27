// Модуль zapret2: процесс nfqws2 в службе vpnguard-nfqws2, стратегии (наборы параметров), проверка сайтов,
// автоподбор, свои списки. На Linux nfqws2 обрабатывает и трафик клиентов — ретранслятор не нужен.
// Параметры стратегий в комплекте — примеры синтаксиса zapret2; рабочие под вашего провайдера подбираются тестом.
package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type zStrategy struct{ Name, Args, Last string }
type zapret2 struct {
	probeMu               sync.Mutex
	checkedAt             time.Time
	videoHost, videoJS    string
	videoAt, videoAttempt time.Time
	base
	strat        []zStrategy
	running      string
	sites        [][]string
	probeHistory [][]string
	fails        int
	retryAt      time.Time
	startErr     string
}

const zUnit, zArgs = "vpnguard-nfqws2", "/etc/vpnguard/nfqws2.args"

func init()                              { Register(&zapret2{}) }
func (m *zapret2) ID() string            { return "zapret" }
func (m *zapret2) Name() string          { return "zapret2" }
func (m *zapret2) Color() string         { return "#ff8a3d" }
func (m *zapret2) Order() int            { return 30 }
func (m *zapret2) Period() time.Duration { return 30 * time.Second }
func (m *zapret2) load() {
	if m.strat != nil {
		return
	}
	if !loadJSON("zapret2.json", &m.strat) || len(m.strat) == 0 {
		m.strat = builtinZapretStrategies()
	}
}

const zapretBaseArgs = "--qnum=200 --lua-init=@lua/zapret-lib.lua --lua-init=@lua/zapret-antidpi.lua --payload=tls_client_hello"

var zapretStepArgs = map[string]string{
	"fake":          "--lua-desync=fake:blob=fake_default_tls:tcp_md5",
	"multisplit":    "--lua-desync=multisplit:pos=midsld",
	"multidisorder": "--lua-desync=multidisorder:pos=1,midsld",
	"hostfakesplit": "--lua-desync=hostfakesplit:host=www.google.com",
}

func builtinZapretStrategies() []zStrategy {
	base := zapretBaseArgs + " "
	return []zStrategy{
		{Name: "fake", Args: base + zapretStepArgs["fake"]},
		{Name: "fake + multisplit", Args: base + zapretStepArgs["fake"] + " " + zapretStepArgs["multisplit"]},
		{Name: "multidisorder", Args: base + zapretStepArgs["multidisorder"]},
		{Name: "hostfakesplit", Args: base + zapretStepArgs["hostfakesplit"]},
	}
}
func (m *zapret2) targets() []string {
	value := cfg("zapret.targets", zapretDefaultTargets)
	if value == zapretLegacyTargets {
		value = zapretDefaultTargets
	}
	var targets []string
	seen := map[string]bool{}
	for _, target := range strings.Split(value, ",") {
		target = strings.TrimSpace(target)
		if target != "" && !seen[target] {
			targets = append(targets, target)
			seen[target] = true
		}
	}
	if cfgBool("zapret.videoCheck", true) {
		for _, target := range []string{"ytvideo", "ytspeed"} {
			if !seen[target] {
				targets = append(targets, target)
			}
		}
	}
	return targets
}
func (m *zapret2) apply(i int) bool {
	m.running, m.startErr = "", ""
	m.checkedAt = time.Time{}
	if err := S.WriteFile(zArgs, m.strat[i].Args+"\n", 0o644); err != nil {
		m.startErr = "Не удалось записать параметры nfqws2"
		return false
	}
	out, code := run("systemctl", "restart", zUnit)
	if code != 0 {
		m.startErr = "Запуск nfqws2: " + firstLine(out)
		return false
	}
	time.Sleep(200 * time.Millisecond)
	if !active(zUnit) {
		m.startErr = "nfqws2 завершился при запуске — проверьте журнал службы"
		return false
	}
	m.running = m.strat[i].Name
	return true
}

type siteCheck struct {
	passed, total int
	setupError    string
	report        []string
}

func (s siteCheck) summary() string {
	if s.setupError != "" {
		return s.setupError
	}
	return fmt.Sprintf("Пройдено проверок шлюза: %d из %d", s.passed, s.total)
}

func probeResourcesAvailable() string {
	rules, code := run("ip", "-4", "rule", "show", "pref", "1198")
	if code != 0 {
		return "Не удалось прочитать правила маршрутизации для проверки"
	}
	if strings.TrimSpace(rules) != "" {
		return "Приоритет 1198 занят, проверка сайтов пропущена"
	}
	tables, code := run("nft", "list", "tables")
	if code != 0 {
		return "Не удалось прочитать список таблиц nftables"
	}
	for _, line := range strings.Split(tables, "\n") {
		if strings.TrimSpace(line) == "table inet vpnguard_zapret_probe" {
			return "Таблица nftables для проверки уже занята"
		}
	}
	return ""
}

func (m *zapret2) check() (result siteCheck) {
	m.probeMu.Lock()
	defer m.probeMu.Unlock()
	var rows [][]string
	defer func() {
		m.mu.Lock()
		m.sites = rows
		entry := []string{time.Now().UTC().Format(time.RFC3339), result.summary()}
		m.probeHistory = append([][]string{entry}, m.probeHistory[:min(15, len(m.probeHistory))]...)
		m.mu.Unlock()
	}()
	targets := m.targets()
	result.total = len(targets)
	if len(targets) == 0 {
		result.setupError = "Список целей пуст"
		return
	}
	if reason := probeResourcesAvailable(); reason != "" {
		result.setupError = reason
		return
	}
	addressOutput, addressCode := run("ip", "-4", "-o", "addr", "show", "dev", wanIface(), "scope", "global")
	address := ""
	fields := strings.Fields(addressOutput)
	for i, field := range fields {
		if field == "inet" && i+1 < len(fields) {
			address = strings.Split(fields[i+1], "/")[0]
			break
		}
	}
	if addressCode != 0 || net.ParseIP(address) == nil {
		result.setupError = "IPv4-адрес интерфейса провайдера не найден"
		return
	}
	// Probe only our curl source ports. Client routing and other local traffic stay untouched.
	script := fmt.Sprintf("create table inet vpnguard_zapret_probe\ntable inet vpnguard_zapret_probe { chain route_probe { type route hook output priority mangle; policy accept; meta mark & 0x40000000 != 0 return; tcp sport 42000-42099 tcp dport {80,443} meta mark set 0x1e; }\n chain output { type filter hook postrouting priority mangle; policy accept; meta mark 0x1e oifname %q tcp sport 42000-42099 tcp dport { 80, 443 } ct original packets 1-9 counter queue num 200 bypass; }\n}\n", wanIface())
	if _, code := S.Run(20*time.Second, script, "nft", "-f", "-"); code != 0 {
		result.setupError = "Не удалось применить временные правила nftables для проверки"
		return
	}
	defer run("nft", "delete", "table", "inet", "vpnguard_zapret_probe")
	if _, code := run("ip", "rule", "add", "fwmark", "0x1e", "lookup", "main", "priority", "1198"); code != 0 {
		result.setupError = "Не удалось создать правило маршрутизации проверки"
		return
	}
	defer run("ip", "rule", "del", "fwmark", "0x1e", "lookup", "main", "priority", "1198")
	if cfgBool("zapret.videoCheck", true) {
		m.discoverVideo(address)
	}
	rows = make([][]string, len(targets))
	report := make([]string, len(targets))
	passed := make([]bool, len(targets))
	var probes sync.WaitGroup
	slots := make(chan struct{}, 3)
	for i, target := range targets {
		probes.Add(1)
		go func(i int, target string) {
			defer probes.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			var detail string
			rows[i], detail, passed[i] = m.checkTarget(address, target)
			report[i] = reportTarget(target, i) + " | " + detail
		}(i, target)
	}
	probes.Wait()
	result.report = report
	for _, ok := range passed {
		if ok {
			result.passed++
		}
	}
	return
}
func (m *zapret2) index(name string) int {
	for i, s := range m.strat {
		if s.Name == name {
			return i
		}
	}
	return -1
}

// pick — подбор: по очереди запускает каждую стратегию и считает открывшиеся сайты.
func (m *zapret2) pick() bool {
	m.busy("подбор стратегии")
	defer m.busy("")
	m.probeMu.Lock()
	reason := probeResourcesAvailable()
	m.probeMu.Unlock()
	if reason != "" {
		m.startErr = reason
		return false
	}
	previous := m.index(m.running)
	best, bestN := -1, 0
	for i := range m.strat {
		if !m.apply(i) {
			m.strat[i].Last = m.startErr
			continue
		}
		time.Sleep(time.Duration(cfgInt("zapret.settleMs", 300)) * time.Millisecond)
		check := m.check()
		if check.setupError != "" {
			if previous >= 0 && previous != i {
				m.apply(previous)
			}
			m.startErr = check.setupError
			return false
		}
		n := check.passed
		m.strat[i].Last = check.summary()
		if n > bestN {
			best, bestN = i, n
		}
	}
	saveJSON("zapret2.json", m.strat)
	if best < 0 {
		Decide("ERROR", "zapret2: ни одна стратегия не открывает сайты → выход отключён, трафик уйдёт на резерв; повтор через %d мин", cfgInt("zapret.retryMin", 120))
		m.retryAt = time.Now().Add(time.Duration(cfgInt("zapret.retryMin", 120)) * time.Minute)
		run("systemctl", "stop", zUnit)
		return false
	}
	if !m.apply(best) {
		return false
	}
	setCfg("zapret.picked", m.strat[best].Name)
	m.check()
	Decide("INFO", "zapret2: подобрана стратегия «%s» (%s сайтов)", m.strat[best].Name, m.strat[best].Last)
	return true
}
func (m *zapret2) want() string {
	if s := cfg("zapret.strategy", ""); s != "" {
		return s
	}
	return cfg("zapret.picked", "")
}
func (m *zapret2) Tick() {
	m.tk.Lock()
	defer m.tk.Unlock()
	m.load()
	if cfg("zapret.enabled", "true") != "true" {
		if active(zUnit) {
			run("systemctl", "stop", zUnit)
		}
		m.setSt(-1, false, "Выключен", "YouTube и Discord идут по правилу резерва")
		return
	}
	if time.Now().Before(m.retryAt) {
		m.setSt(2, false, "Нет рабочей стратегии", "повторный подбор в "+m.retryAt.Format("15:04"))
		return
	}
	i := m.index(m.want())
	if i < 0 {
		if !m.pick() {
			if m.startErr != "" {
				m.setSt(2, false, "Ошибка запуска или проверки", m.startErr)
			} else {
				m.setSt(2, false, "Нет рабочей стратегии", "ни одна стратегия не открыла сайты")
			}
			return
		}
	} else if m.adoptRunning(i) {
		// Агент перезапущен, но рабочий nfqws2 с этими параметрами уже запущен.
	} else if !active(zUnit) || m.running != m.strat[i].Name {
		if !m.apply(i) {
			m.setSt(2, false, "nfqws2 не запущен", m.startErr)
			return
		}
	}
	if !m.checkedAt.IsZero() && time.Since(m.checkedAt) < time.Duration(max(1, cfgInt("zapret.healthCheckMin", 10)))*time.Minute && m.Status().State != "" {
		return
	}
	check := m.check()
	if check.setupError != "" {
		m.setSt(1, m.Status().Up && active(zUnit), "Проверка сайтов недоступна", check.setupError)
		return
	}
	m.checkedAt = time.Now()
	n, all := check.passed, check.total
	kv := [][2]string{{"Стратегия", m.running}, {"Сайты", fmt.Sprintf("%d из %d открываются", n, all)}, {"Служба", zUnit}}
	if n == all && active(zUnit) {
		m.fails = 0
		m.setSt(0, true, "Работает", "", kv...)
		return
	}
	m.fails++
	if n > 0 {
		m.setSt(1, true, "Часть сайтов не открывается", "", kv...)
	} else {
		m.setSt(2, false, "Сайты не открываются", "стратегия «"+m.running+"» перестала работать", kv...)
	}
	if m.fails >= 2 && cfg("zapret.strategy", "") == "" && allow("zapret.pick", 3, time.Hour) {
		Decide("WARN", "zapret2: сайты не открываются %d проверки подряд → переподбор стратегии", m.fails)
		m.fails = 0
		if m.pick() {
			m.setSt(0, true, "Работает", "", [2]string{"Стратегия", m.running})
		}
	}
}

func (m *zapret2) adoptRunning(i int) bool {
	if m.running != "" || i < 0 || i >= len(m.strat) || !active(zUnit) {
		return false
	}
	args, err := S.ReadFile(zArgs)
	if err != nil || strings.TrimSpace(args) != strings.TrimSpace(m.strat[i].Args) {
		return false
	}
	m.running = m.strat[i].Name
	Log("INFO", "zapret2: работающий nfqws2 принят без перезапуска (%s)", m.running)
	return true
}
func (m *zapret2) Exit() *Exit { return &Exit{Iface: wanIface(), Table: 0, Mark: 0x13, Queue: true} }
func (m *zapret2) Fields() []Field {
	m.load()
	o := []Opt{{"", "(авто) подбирать"}}
	for _, s := range m.strat {
		o = append(o, Opt{s.Name, s.Name})
	}
	return []Field{fb("zapret.enabled", "zapret2 включён", "bool", "true", ""),
		fb("zapret.strategy", "Стратегия", "select", "", "В режиме «авто» агент переподбирает её сам, когда сайты перестают открываться", o...),
		fb("zapret.targets", "Сайты для проверки, через запятую", "text", zapretDefaultTargets, ""),
		fb("zapret.healthCheckMin", "Проверять сайты каждые, мин", "number", "10", "Ручная проверка и подбор запускаются сразу; загрузка JS плеера расходует трафик."),
		fb("zapret.videoCheck", "Проверять видеосервер и скорость YouTube", "bool", "true", "Скорость оценивается по JS плеера, как в Windows; минимум 1,5 Мбит/с. Это не проверка воспроизведения ролика."),
		fb("zapret.hosts", "Свои домены для zapret2", "textarea", "", "По одному в строке. Попадают в список nfqws2 и в правило маршрутов «списки zapret»"),
		fb("zapret.exclude", "Исключения", "textarea", "", "Домены, которые zapret2 не должен трогать"),
		fb("zapret.retryMin", "Повтор подбора после неудачи, мин", "number", "120", "")}
}
func (m *zapret2) Set(k, v string) error {
	setCfg(k, v)
	if k == "zapret.hosts" || k == "zapret.exclude" {
		_ = S.WriteFile("/etc/vpnguard/zapret-"+strings.TrimPrefix(k, "zapret.")+".txt", v+"\n", 0o644)
		run("systemctl", "restart", zUnit)
		Emit("routes.changed", "zapret")
	}
	m.retryAt = time.Time{}
	m.checkedAt = time.Time{}
	go m.Tick()
	return nil
}
func (m *zapret2) Actions() []Action {
	var presets []Opt
	for _, preset := range builtinZapretStrategies() {
		presets = append(presets, Opt{preset.Name, preset.Name})
	}
	selectedModel := localModels[0].V
	configured := aiModel()
	for _, opt := range localModels {
		if opt.V == configured {
			selectedModel = configured
			break
		}
	}
	return []Action{
		{ID: "ai-setup", Title: "Настроить локальный ИИ", Confirm: "При необходимости будут загружены Ollama и выбранная модель. Загрузка может занять несколько гигабайт.", Args: []Field{{Key: "model", Title: "Модель", Type: "select", Value: selectedModel, Options: localModels}}},
		{ID: "ai-draft", Title: "Создать стратегию с ИИ", Args: []Field{
			{Key: "base", Title: "Исходная стратегия", Type: "select", Value: presets[0].V, Options: presets},
			{Key: "scenario", Title: "Что проверить", Type: "select", Value: "youtube", Options: []Opt{{"youtube", "Воспроизведение YouTube"}, {"discord", "Соединение Discord Gateway"}}},
			{Key: "symptom", Title: "Наблюдение на устройстве", Type: "select", Value: "unknown", Options: []Opt{{"unknown", "Пока нет измерения"}, {"failed", "Приложение не работает, HTTPS-контроль проходит"}, {"intermittent", "Приложение периодически прерывается, HTTPS-контроль проходит"}}},
		}},
		{ID: "ai-draft-latest", Title: "Открыть последний черновик ИИ"},
		{ID: "trial", Title: "Испытать запуск профиля", Args: []Field{
			{Key: "preset", Title: "Встроенный профиль", Type: "select", Value: presets[0].V, Options: presets,
				Help: "Испытание проходит в отдельной сети Linux."},
			{Key: "mode", Title: "Что проверить", Type: "select", Value: "http",
				Options: []Opt{{"http", "Запуск и локальный HTTP-обмен"}, {"startup", "Только запуск"}}},
		}},
		{ID: "pick", Title: "Подобрать стратегию", Confirm: "Во время подбора YouTube и Discord могут не открываться. Начать?"},
		{ID: "check", Title: "Проверить сайты сейчас"},
		{ID: "add", Title: "Добавить стратегию", Args: []Field{{Key: "name", Title: "Название", Type: "text"}, {Key: "args", Title: "Параметры nfqws2", Type: "textarea"}}},
		{ID: "restart", Title: "Перезапустить nfqws2"}}
}
func (m *zapret2) Do(id string, a map[string]string) (string, error) {
	if id == "ai-setup" {
		return setupLocalAI(a["model"])
	}
	if id == "trial" {
		return trialZapretPreset(a["preset"], a["mode"])
	}
	m.load()
	i := m.index(a["row"])
	switch id {
	case "pick":
		m.retryAt = time.Time{}
		go func() { m.tk.Lock(); m.pick(); m.tk.Unlock(); m.Tick() }()
		return "Подбор запущен, результаты появятся в таблице", nil
	case "check":
		check := m.check()
		return check.summary(), nil
	case "restart":
		run("systemctl", "restart", zUnit)
		return "nfqws2 перезапущен", nil
	case "add":
		n, args := strings.TrimSpace(a["name"]), strings.TrimSpace(a["args"])
		if n == "" || args == "" {
			return "", errors.New("заполните название и параметры")
		}
		if m.index(n) >= 0 {
			return "", errors.New("стратегия с таким названием уже есть")
		}
		if !strings.Contains(args, "--qnum=") {
			args = "--qnum=200 " + args
		}
		m.strat = append(m.strat, zStrategy{Name: n, Args: args})
		saveJSON("zapret2.json", m.strat)
		return "Стратегия добавлена", nil
	case "select":
		if i < 0 {
			return "", errors.New("стратегия не найдена")
		}
		return "Выбрана стратегия «" + a["row"] + "»", m.Set("zapret.strategy", a["row"])
	case "delete":
		if i < 0 || len(m.strat) < 2 {
			return "", errors.New("нельзя удалить последнюю стратегию")
		}
		m.strat = append(m.strat[:i], m.strat[i+1:]...)
		saveJSON("zapret2.json", m.strat)
		return "Стратегия удалена", nil
	}
	return "", errors.New("неизвестное действие")
}
func (m *zapret2) Tables() []Table {
	m.load()
	m.mu.Lock()
	sites := m.sites
	history := m.probeHistory
	m.mu.Unlock()
	var rows [][]string
	for _, s := range m.strat {
		st := ""
		if s.Name == m.running {
			st = "запущена"
		}
		rows = append(rows, []string{s.Name, s.Args, s.Last, st})
	}
	return []Table{{Title: "Проверка сайтов", Cols: []string{"Проверка", "Результат", "Подробности"}, Rows: sites, Empty: "Проверка ещё не выполнялась", Note: "HTTP 403/404 у корня сайта означает, что сервер ответил. Gateway проверяется по HTTPS. Скорость — загрузка JS плеера, как в Windows; воспроизведение ролика, WebSocket и голос Discord здесь не проверяются."},
		{Title: "История проверок шлюза", Cols: []string{"Время UTC", "Результат"}, Rows: history, Empty: "Нет завершённых проверок", Note: "Последние 16 попыток с момента запуска агента. Ошибка подготовки сохраняется отдельно от результата запросов."},
		{Title: "Стратегии", Cols: []string{"Название", "Параметры nfqws2", "Последний подбор", "Состояние"}, Rows: rows,
			Actions: []Action{{ID: "select", Title: "Выбрать"}, {ID: "delete", Title: "Удалить", Danger: true, Confirm: "Удалить стратегию?"}}}, aiSetupTable()}
}
func (m *zapret2) Checks() []Check {
	return []Check{
		{ID: "zapret.unit", Title: "Служба nfqws2 работает", FixTitle: "Перезапустить",
			Run: func() Finding {
				return Finding{OK: cfg("zapret.enabled", "true") != "true" || active(zUnit), Text: zUnit}
			},
			Fix: func() (string, error) {
				run("systemctl", "restart", zUnit)
				return "служба перезапущена", nil
			}},
		{ID: "zapret.sites", Title: "Сайты открываются напрямую через zapret2", FixTitle: "Переподобрать стратегию",
			Run: func() Finding {
				check := m.check()
				if check.setupError != "" {
					return Finding{SkipFix: true, Text: check.setupError, Report: []string{check.setupError}, Hint: "Проверьте условия запуска теста на шлюзе"}
				}
				return Finding{OK: check.passed == check.total, Text: check.summary(), Report: check.report, Hint: "Подробности по каждой цели есть в отчёте проверки"}
			},
			Fix: func() (string, error) {
				m.retryAt = time.Time{}
				if m.pick() {
					return "подобрана стратегия «" + m.running + "»", nil
				}
				return "", errors.New("ни одна стратегия не подошла")
			}},
	}
}
