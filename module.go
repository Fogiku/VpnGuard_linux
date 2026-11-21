// Модули. Каждый компонент (MeduzaVPN, AmneziaWG, zapret2, WG-Server …) — отдельный файл mod_*.go,
// который реализует Module и регистрируется в init(). Модуль сам описывает свою веб-страницу:
// поля настроек, действия, таблицы и проверки, — поэтому новый модуль не требует правок интерфейса.
package main

import (
	"slices"
	"sort"
	"sync"
	"time"
)

type Status struct {
	Level int         `json:"level"` // 0 норма, 1 предупреждение, 2 сбой, -1 выключен
	State string      `json:"state"`
	Why   string      `json:"why"`
	Up    bool        `json:"up"` // может ли выход нести трафик
	Busy  string      `json:"busy"`
	KV    [][2]string `json:"kv"`
}
type Opt struct{ V, T string }
type Field struct {
	Key     string `json:"key"`
	Title   string `json:"title"`
	Type    string `json:"type"` // text, number, bool, select, textarea, password
	Value   string `json:"value"`
	Help    string `json:"help,omitempty"`
	Options []Opt  `json:"options,omitempty"`
	Group   string `json:"group,omitempty"` // поля одной группы показываются отдельным блоком с этим заголовком
}
type Action struct {
	ID      string  `json:"id"`
	Title   string  `json:"title"`
	Confirm string  `json:"confirm,omitempty"`
	Danger  bool    `json:"danger,omitempty"`
	Args    []Field `json:"args,omitempty"`
}
type Table struct {
	ID          string     `json:"id,omitempty"`
	ProblemRows []int      `json:"problemRows,omitempty"`
	Title       string     `json:"title"`
	Cols        []string   `json:"cols"`
	Rows        [][]string `json:"rows"` // первая ячейка — ключ строки, передаётся действию как row
	Actions     []Action   `json:"actions,omitempty"`
	Empty       string     `json:"empty,omitempty"`
	Text        string     `json:"text,omitempty"` // блок текста вместо таблицы (конфиг, журнал)
	Img         string     `json:"img,omitempty"`  // картинка рядом с текстом (QR-код), data: URI
	Note        string     `json:"note,omitempty"` // пояснение над содержимым блока
	File        string     `json:"file,omitempty"` // имя файла: у текста появляются кнопки «Скопировать» и «Скачать»
	Top         bool       `json:"top,omitempty"`  // показать блок над кнопками управления (вход, предупреждения)
}
type Finding struct {
	SkipFix bool     `json:"-"`                // Причина сбоя делает штатное исправление неприменимым.
	Report  []string `json:"report,omitempty"` // Одобренные для выгрузки подробности проверки.
	OK      bool     `json:"ok"`
	Text    string   `json:"text"`
	Hint    string   `json:"hint,omitempty"`
}
type Check struct {
	ID       string
	Title    string
	FixTitle string
	Run      func() Finding
	Fix      func() (string, error)
}
type Exit struct {
	AutoRoutes bool   `json:"-"` // Дополнительный туннель запрашивает стабильные Mark и Table по ID модуля.
	Iface      string `json:"iface"`
	Table      int    `json:"table"` // таблица маршрутизации; 0 — основная
	Mark       int    `json:"mark"`
	Queue      bool   `json:"queue"` // трафик проходит через очередь nfqws2
	Block      bool   `json:"block"`
}

type Module interface {
	ID() string
	Name() string
	Color() string
	Order() int
	Period() time.Duration
	Tick()
	Status() Status
	Fields() []Field
	Set(key, val string) error
	Actions() []Action
	Do(id string, args map[string]string) (string, error)
	Tables() []Table
	Checks() []Check
	Exit() *Exit
	Metrics() map[string]float64
}

// base — общая часть модулей: состояние под блокировкой и ответы по умолчанию.
type base struct {
	tk  sync.Mutex // одна проверка модуля за раз
	mu  sync.Mutex
	st  Status
	met map[string]float64
}

func (b *base) Status() Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.st
	st.KV = slices.Clone(st.KV)
	return st
}
func (b *base) setSt(level int, up bool, state, why string, kv ...[2]string) {
	b.mu.Lock()
	b.st.Level, b.st.Up, b.st.State, b.st.Why, b.st.KV = level, up, state, why, slices.Clone(kv)
	b.mu.Unlock()
}
func (b *base) busy(s string) { b.mu.Lock(); b.st.Busy = s; b.mu.Unlock() }
func (b *base) metric(k string, v float64) {
	b.mu.Lock()
	if b.met == nil {
		b.met = map[string]float64{}
	}
	b.met[k] = v
	b.mu.Unlock()
}
func (b *base) Metrics() map[string]float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string]float64{}
	for k, v := range b.met {
		out[k] = v
	}
	return out
}
func (b *base) Order() int                                   { return 50 }
func (b *base) Period() time.Duration                        { return 15 * time.Second }
func (b *base) Fields() []Field                              { return nil }
func (b *base) Set(k, v string) error                        { setCfg(k, v); return nil }
func (b *base) Actions() []Action                            { return nil }
func (b *base) Tables() []Table                              { return nil }
func (b *base) Checks() []Check                              { return nil }
func (b *base) Exit() *Exit                                  { return nil }
func (b *base) Do(string, map[string]string) (string, error) { return "", nil }

// Необязательные свойства модуля.
type noPager interface{ NoPage() bool }            // своей вкладки нет (состояние показано на главной и в диагностике)
type fieldsFirster interface{ FieldsFirst() bool } // настройки выше таблиц (например, настройки сервера)

func hasPage(m Module) bool {
	if np, ok := m.(noPager); ok && np.NoPage() {
		return false
	}
	return len(m.Actions()) > 0 || len(m.Fields()) > 0
}
func fieldsFirst(m Module) bool { f, ok := m.(fieldsFirster); return ok && f.FieldsFirst() }

// служебный модуль (удалённая диагностика): не узел сети — нет плитки на главной и графика в мониторинге
type auxer interface{ Aux() bool }

func isAux(m Module) bool { a, ok := m.(auxer); return ok && a.Aux() }

var Mods []Module

func Register(m Module) { Mods = append(Mods, m) }
func mod(id string) Module {
	for _, m := range Mods {
		if m.ID() == id {
			return m
		}
	}
	return nil
}

// startModules: у каждого модуля свой поток и свой ритм — долгое действие одного не задерживает остальные.
func startModules() {
	sort.SliceStable(Mods, func(i, j int) bool { return Mods[i].Order() < Mods[j].Order() })
	var initial sync.WaitGroup
	initial.Add(len(Mods))
	for _, m := range Mods {
		go func(m Module) {
			prev := m.Status().Up
			first := true
			for {
				func() {
					defer func() {
						if r := recover(); r != nil {
							Log("ERROR", "модуль %s: сбой в проверке: %v", m.ID(), r)
						}
					}()
					m.Tick()
					if first {
						first = false
						initial.Done()
					}
				}()
				if up := m.Status().Up; up != prev {
					prev = up
					Emit("exit.changed", m.ID())
				}
				time.Sleep(m.Period())
			}
		}(m)
	}
	go func() {
		initial.Wait()
		routesStarting.Store(false)
		applySoon("начальные состояния модулей проверены")
	}()
}

// rate — скорость по счётчику байт между двумя вызовами.
type rate struct {
	last float64
	at   time.Time
}

func (r *rate) bps(total float64) float64 {
	now := time.Now()
	defer func() { r.last, r.at = total, now }()
	if r.at.IsZero() || total < r.last {
		return 0
	}
	if dt := now.Sub(r.at).Seconds(); dt > 0 {
		return (total - r.last) * 8 / dt
	}
	return 0
}
func fb(key, title, typ, def, help string, opts ...Opt) Field {
	return Field{Key: key, Title: title, Type: typ, Value: cfg(key, def), Help: help, Options: opts}
}
