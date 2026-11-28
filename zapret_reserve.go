package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Verified candidates are preferred. Fill remaining slots from the configured profiles.
func (m *zapret2) reserveIndices(current int) []int {
	seen := map[string]bool{}
	if current >= 0 {
		seen[m.strat[current].Args] = true
	}
	var slots []int
	add := func(i int) {
		s := m.strat[i]
		if len(slots) < 3 && !seen[s.Args] {
			slots = append(slots, i)
			seen[s.Args] = true
		}
	}
	for i := len(m.strat) - 1; i >= 0; i-- {
		if m.strat[i].Qualified {
			add(i)
		}
	}
	for i := range m.strat {
		add(i)
	}
	return slots
}

func improvesTargets(base, candidate siteCheck) bool {
	if base.setupError != "" || candidate.setupError != "" || len(base.results) == 0 || len(base.results) != len(candidate.results) {
		return false
	}
	better := false
	for target, was := range base.results {
		now, ok := candidate.results[target]
		if !ok || was && !now {
			return false
		}
		better = better || now && !was
	}
	return better
}

type reserveAttempt struct {
	Revision string `json:"revision"`
	Result   string `json:"result"`
}
type reserveRecovery struct {
	Updated  string           `json:"updated"`
	Original string           `json:"original"`
	Status   string           `json:"status"`
	Attempts []reserveAttempt `json:"attempts"`
}

func latestReserveRecovery() *reserveRecovery {
	var last reserveRecovery
	if json.Unmarshal([]byte(cfg("zapret.reserveRecovery", "")), &last) != nil || last.Status == "" {
		return nil
	}
	return &last
}

// Commit the selection and its verified outcome in the same config write.
func (r *reserveRecovery) save(status, selection string) error {
	r.Updated = time.Now().UTC().Format(time.RFC3339)
	r.Status = status
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	values := map[string]string{"zapret.reserveRecovery": string(data)}
	if selection != "" {
		values["zapret.picked"] = selection
	}
	return setConfigValues(values)
}

func (m *zapret2) verifyReserve(i int, base siteCheck) (siteCheck, string) {
	if !m.apply(i) {
		return siteCheck{}, "Резерв не запустился"
	}
	time.Sleep(time.Duration(cfgInt("zapret.settleMs", 300)) * time.Millisecond)
	var check siteCheck
	for _, stage := range []string{"Первая проверка", "Повторная проверка"} {
		check = m.check()
		if check.setupError != "" {
			return check, stage + " недоступна"
		}
		if !active(zUnit) {
			return check, "Служба остановилась"
		}
		if !improvesTargets(base, check) {
			for target, was := range base.results {
				if was && !check.results[target] {
					return check, stage + ": потеря ранее доступной цели"
				}
			}
			return check, stage + ": улучшение не подтверждено"
		}
	}
	return check, ""
}

func (m *zapret2) recoverReserve(base siteCheck) {
	current := m.index(m.running)
	if current < 0 {
		return
	}
	original := m.strat[current]
	defer m.busy("")
	record := reserveRecovery{Original: draftHash(original.Args)}
	for slot, i := range m.reserveIndices(current) {
		m.busy(fmt.Sprintf("Проверяется резерв %d · %s", slot+1, m.strat[i].Name))
		record.Attempts = append(record.Attempts, reserveAttempt{Revision: draftHash(m.strat[i].Args), Result: "Проверка начата"})
		attempt := &record.Attempts[len(record.Attempts)-1]
		if err := record.save("Начата проверка резерва", ""); err != nil {
			Decide("ERROR", "zapret2: не удалось сохранить начало проверки резерва: %v", err)
			return
		}
		verified, reason := m.verifyReserve(i, base)
		if reason == "" {
			attempt.Result = "Улучшение подтверждено дважды"
			if err := record.save("Резерв принят", m.strat[i].Name); err == nil {
				m.checkedAt = time.Now()
				m.recordHealth(verified)
				Decide("INFO", "zapret2: резерв «%s» заменил «%s», %s", m.running, original.Name, verified.summary())
				return
			}
			reason = "Не удалось сохранить выбор резерва"
		}
		attempt.Result = reason
		if !m.apply(current) {
			if err := record.save("Ошибка возврата к исходному профилю", ""); err != nil {
				Log("ERROR", "zapret2: запись результата: %v", err)
			}
			m.setSt(2, false, "Не удалось восстановить исходную стратегию", m.startErr)
			Decide("ERROR", "zapret2: ошибка возврата к «%s»: %s", original.Name, m.startErr)
			return
		}
		if err := record.save("Исходный профиль запущен", ""); err != nil {
			Log("ERROR", "zapret2: запись возврата: %v", err)
			return
		}
	}
	m.checkedAt = time.Now()
	result := m.check()
	status := "Оставлен исходный профиль · " + result.summary()
	if result.setupError != "" {
		status = "Исходный профиль запущен, итоговая проверка недоступна"
		m.setSt(1, false, "Проверка после возврата недоступна", result.setupError)
	} else {
		m.recordHealth(result)
	}
	if err := record.save(status, ""); err != nil {
		Log("ERROR", "zapret2: запись результата: %v", err)
	}
	Decide("WARN", "zapret2: резерв не подтвердил улучшение, оставлена стратегия «%s»", original.Name)
}

func reserveRecoveryTable() Table {
	table := Table{Title: "Последнее автоматическое переключение", Cols: []string{"SHA-256 резерва", "Результат"}, Empty: "Автоматических попыток ещё не было"}
	if last := latestReserveRecovery(); last != nil {
		table.Note = last.Updated + " · " + last.Status + " · исходный SHA-256 " + last.Original
		for _, a := range last.Attempts {
			table.Rows = append(table.Rows, []string{a.Revision, a.Result})
		}
	}
	return table
}

type reservePair struct {
	UTC    []time.Time                          `json:"utc"`
	States []string                             `json:"states"`
	Egress []map[string]struct{ Status string } `json:"egress"`
}
type reserveSeries struct {
	Outcome string        `json:"outcome"`
	Pairs   []reservePair `json:"pairs"`
}
type reserveReport struct {
	Schema        int
	Source        string
	ProfileSource string `json:"profile_source"`
	Profiles      []string
	Comparison    map[string]reserveSeries
}

func (r reserveReport) qualifies(d zapretDraft, now time.Time) error {
	if r.Schema != 1 || r.Source != "paired_client_browser" || r.ProfileSource != "file_sha256" || len(r.Profiles) != 2 || r.Profiles[0] != d.BaseSHA256 || r.Profiles[1] != d.SHA256 {
		return errors.New("требуется парный отчёт для этих двух файлов профилей")
	}
	target := d.Scenario
	if target == "discord" {
		target = "discord_gateway"
	}
	if target != "youtube" && target != "discord_gateway" {
		return errors.New("неизвестное приложение")
	}
	if len(r.Comparison) != 2 {
		return errors.New("в отчёте нужны YouTube и Discord Gateway")
	}
	for _, service := range []string{"youtube", "discord_gateway"} {
		series := r.Comparison[service]
		if len(series.Pairs) < 2 || len(series.Pairs) > 5 || len(series.Pairs) != len(r.Comparison[target].Pairs) {
			return fmt.Errorf("%s: нужны повторные парные пробы обоих приложений", service)
		}
		var prev [2]time.Time
		for j, p := range series.Pairs {
			if len(p.UTC) != 2 || len(p.States) != 2 || p.States[1] != "observed" || (p.States[0] != "observed" && p.States[0] != "failure") {
				return fmt.Errorf("%s: нет подтверждения доступности кандидата и исправного контроля", service)
			}
			for i, t := range p.UTC {
				ref := r.Comparison[target].Pairs[j].UTC
				if len(ref) != 2 || !t.Equal(ref[i]) || t.After(now) || now.Sub(t) > 24*time.Hour || !t.After(prev[i]) {
					return errors.New("несовместимые или устаревшие измерения")
				}
				prev[i] = t
			}
			if delta := p.UTC[0].Sub(p.UTC[1]); delta < -2*time.Minute || delta > 2*time.Minute {
				return errors.New("слишком большой интервал между парными пробами")
			}
			if p.Egress != nil && (len(p.Egress) != 2 || len(p.Egress[0]) == 0 || len(p.Egress[0]) != len(p.Egress[1])) {
				return errors.New("неполная проверка выхода")
			}
			if len(p.Egress) == 2 {
				for family, check := range p.Egress[0] {
					if check.Status != "matched" || p.Egress[1][family].Status != "matched" {
						return errors.New("выход не подтверждён")
					}
				}
			}
			outcome := "both_observed"
			if p.States[0] == "failure" {
				outcome = "only_second_observed"
			}
			if outcome != series.Outcome || service == target && outcome != "only_second_observed" {
				return fmt.Errorf("%s: серия не подтвердила требуемое улучшение", service)
			}
		}
	}
	return nil
}

func (m *zapret2) admitReserve(r reserveReport) (string, error) {
	m.tk.Lock()
	defer m.tk.Unlock()
	if !draftRequest.TryLock() {
		return "", errors.New("черновик занят, повторите добавление в резерв")
	}
	defer draftRequest.Unlock()
	d, err := readLatestDraft()
	if err != nil {
		return "", err
	}
	if err = r.qualifies(d, time.Now()); err != nil {
		return "", err
	}
	current, err := S.ReadFile(zArgs)
	if err != nil || current != d.Original+"\n" || !active(zUnit) {
		return "", errors.New("рабочий профиль изменился или служба недоступна")
	}
	m.load()
	next := append([]zStrategy(nil), m.strat...)
	name := "ИИ " + d.SHA256[:12]
	for i, s := range next {
		if s.Args == d.Args {
			name = s.Name
			next = append(next[:i], next[i+1:]...)
			break
		}
		if s.Name == name {
			return "", errors.New("название профиля занято")
		}
	}
	next = append(next, zStrategy{Name: name, Args: d.Args, Qualified: true, Last: "Парные пробы YouTube и Discord Gateway пройдены"})
	if err := saveJSON("zapret2.json", next); err != nil {
		return "", err
	}
	m.strat = next
	return "Кандидат добавлен в резерв: " + name, nil
}

func repeatedUnanswered(before, after []flowRow, complete bool) map[dpiRowKey]bool {
	if !complete {
		return nil
	}
	eligible := func(r flowRow) bool {
		return (r.Protocol == "tcp" || r.Protocol == "udp" && r.DestinationPort == 443) && r.Mark>>16&255 == 19 && r.ConntrackID != nil && r.SeenReply != nil && !*r.SeenReply
	}
	first := map[dpiRowKey]bool{}
	for _, r := range before {
		if eligible(r) {
			first[dpiKey(r)] = true
		}
	}
	result := map[dpiRowKey]bool{}
	for _, r := range after {
		if eligible(r) && first[dpiKey(r)] {
			result[dpiKey(r)] = true
		}
	}
	return result
}

func (m *flowModule) unansweredByApp() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.at.IsZero() || m.truncated || time.Since(m.at) > time.Minute {
		return nil
	}
	labels := m.snapshotLabels()
	counts := map[string]int{}
	for key := range m.unanswered {
		app := labels[key].Flow.Application
		if app == "" {
			app = "Unknown"
		}
		counts[app]++
	}
	return counts
}

func draftBaselines() []zStrategy {
	base := builtinZapretStrategies()
	var stored []zStrategy
	if loadJSON("zapret2.json", &stored) {
		for _, s := range stored {
			if s.Qualified {
				base = append(base, s)
			}
		}
	}
	return base
}

// The snapshot is supporting evidence. Unclassified pending connections alone cannot select an application.
func (m *flowModule) maybeDraftFromPending(profileArgs string) {
	if !cfgBool("zapret.passiveDraft", false) || !cfgBool("zapret.enabled", true) || aiModel() == "" {
		return
	}
	counts := m.unansweredByApp()
	byService := map[string]int{}
	for app, n := range counts {
		for _, part := range strings.Split(strings.ToLower(app), ".") {
			switch part {
			case "youtube", "youtubeupload":
				byService["youtube"] += n
			case "discord":
				byService["discord"] += n
			}
		}
	}
	scenario := "youtube"
	if byService["discord"] > byService["youtube"] {
		scenario = "discord"
	}
	if byService[scenario] == 0 {
		if len(counts) > 0 {
			draftWait("Есть потоки без ответа. Привязка к YouTube или Discord не подтверждена")
		} else {
			draftWait("Наблюдение · повторных потоков без ответа не обнаружено")
		}
		return
	}
	raw, err := S.ReadFile(zArgs)
	if err != nil || raw != profileArgs || !active(zUnit) {
		return
	}
	for _, base := range draftBaselines() {
		if raw != base.Args+"\n" {
			continue
		}
		if !allow("zapret.flowDraft", 1, time.Hour) {
			draftWait("Подходящий сигнал обнаружен · действует часовой лимит генерации")
			return
		}
		go func() {
			d, err := generateZapretDraft(base.Name, scenario, "flow_without_observed_reply", aiModel(), "http://127.0.0.1:11434/api/chat")
			if err != nil {
				Log("WARN", "zapret2: генерация по снимку потоков: %v", err)
				return
			}
			Decide("INFO", "zapret2: результат генерации по снимку %s: %s", scenario, d.Status)
		}()
		return
	}
}
