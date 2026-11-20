// Модуль WG-Server: свой сервер WireGuard для клиентов шлюза.
// Сервер: подсеть, порт, MTU; для клиентов — внешний адрес, DNS, AllowedIPs, keepalive; смена ключа сервера;
// правка конфигурации целиком с проверкой; резервные копии перед каждым изменением и восстановление;
// создание сервера заново; состояние службы wg-quick. Клиенты: добавить, QR и конфигурация, отключить,
// переименовать, удалить; состояние и скорость каждого.
package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type WgClient struct {
	Name  string  `json:"name"`
	IP    string  `json:"ip"`
	Priv  string  `json:"priv"` // пусто — клиент добавлен правкой файла, его конфигурации у шлюза нет
	Pub   string  `json:"pub"`
	Psk   string  `json:"psk"`
	Off   bool    `json:"off"`
	Extra string  `json:"extra,omitempty"` // прочие строки [Peer] из правки файла
	On    bool    `json:"on"`              // на связи: рукопожатие моложе 3 минут
	Rx    float64 `json:"rx"`
	Tx    float64 `json:"tx"`
	Seen  string  `json:"seen"`
}
type wgData struct {
	Priv, Pub string
	Clients   []*WgClient
	Extra     []string `json:",omitempty"` // прочие строки [Interface] (PostUp, Table …) из правки файла
}
type wgBackup struct {
	At   string            `json:"at"`
	Why  string            `json:"why"`
	D    wgData            `json:"d"`
	Cfg  map[string]string `json:"cfg"`
	Conf string            `json:"conf"`
}
type wgServer struct {
	base
	d       wgData
	rates   map[string]*[2]rate
	viewIP  string // клиент, чья конфигурация показана на странице
	viewSrv bool   // показана конфигурация сервера
	svc     [3]string
}

var wgMod = &wgServer{rates: map[string]*[2]rate{}}

const wgHidden = "(скрыт)"

var wgKeys = []string{"wg.subnet", "wg.port", "wg.mtu", "wg.endpoint", "wg.dns", "wg.allowed", "wg.keepalive"}

func init()                           { Register(wgMod) }
func (m *wgServer) ID() string        { return "wg" }
func (m *wgServer) Name() string      { return "WG-Server" }
func (m *wgServer) Color() string     { return "#39d0ff" }
func (m *wgServer) Order() int        { return 5 }
func (m *wgServer) FieldsFirst() bool { return true }
func (m *wgServer) iface() string     { return cfg("wg.iface", "wg_server") }
func (m *wgServer) subnet() string    { return cfg("wg.subnet", "10.253.0") }
func (m *wgServer) unit() string      { return "wg-quick@" + m.iface() }
func (m *wgServer) confPath() string {
	return "/etc/wireguard/" + m.iface() + ".conf"
}
func key(cmd, stdin string) string {
	o, _ := S.Run(5*time.Second, stdin, "wg", cmd)
	return strings.TrimSpace(o)
}

// conf — файл сервера; hide — закрытый ключ и общие ключи заменены на «(скрыт)» (для показа и правки в вебе).
func (m *wgServer) conf(hide bool) string {
	h := func(s string) string {
		if hide {
			return wgHidden
		}
		return s
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Файл создаёт VpnGuard. Меняйте его на вкладке WG-Server («Править конфигурацию сервера») — ручные правки будут перезаписаны\n[Interface]\nAddress = %s.1/24\nListenPort = %s\nPrivateKey = %s\n", m.subnet(), cfg("wg.port", "51820"), h(m.d.Priv))
	if mtu := cfg("wg.mtu", "1420"); mtu != "" {
		fmt.Fprintf(&b, "MTU = %s\n", mtu)
	}
	for _, l := range m.d.Extra {
		b.WriteString(l + "\n")
	}
	for _, c := range m.d.Clients {
		if !c.Off {
			fmt.Fprintf(&b, "\n[Peer]\n# %s\nPublicKey = %s\n", c.Name, c.Pub)
			if c.Psk != "" {
				fmt.Fprintf(&b, "PresharedKey = %s\n", h(c.Psk))
			}
			fmt.Fprintf(&b, "AllowedIPs = %s/32\n", c.IP)
			if c.Extra != "" {
				b.WriteString(c.Extra + "\n")
			}
		}
	}
	return b.String()
}
func (m *wgServer) save() {
	saveJSON("wg.json", m.d)
	_ = S.WriteFile(m.confPath(), m.conf(false), 0o600)
	if active(m.unit()) {
		run("bash", "-c", "wg syncconf "+m.iface()+" <(wg-quick strip "+m.iface()+")")
	}
	Emit("routes.changed", "wg")
}

// restart — после смены адреса, MTU или ключа: wg syncconf их не применяет.
func (m *wgServer) restart(why string) {
	Decide("INFO", "WG-Server: %s → перезапуск %s (клиенты переподключатся сами)", why, m.unit())
	run("systemctl", "restart", m.unit())
}
func (m *wgServer) ensure() {
	if m.d.Priv != "" {
		return
	}
	if loadJSON("wg.json", &m.d) && m.d.Priv != "" {
		return
	}
	if m.d.Priv == "" {
		m.d.Priv = key("genkey", "")
		m.d.Pub = key("pubkey", m.d.Priv)
		Decide("INFO", "WG-Server: сервер создан (%s.1/24, UDP %s)", m.subnet(), cfg("wg.port", "51820"))
	}
	m.save()
}
func (m *wgServer) add(name string) (*WgClient, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("введите имя клиента")
	}
	used := map[string]bool{}
	for _, c := range m.d.Clients {
		used[c.IP] = true
		if strings.EqualFold(c.Name, name) {
			return nil, errors.New("клиент с таким именем уже есть")
		}
	}
	for i := 2; i < 255; i++ {
		ip := m.subnet() + "." + strconv.Itoa(i)
		if !used[ip] {
			p := key("genkey", "")
			c := &WgClient{Name: name, IP: ip, Priv: p, Pub: key("pubkey", p), Psk: key("genpsk", "")}
			m.d.Clients = append(m.d.Clients, c)
			m.save()
			return c, nil
		}
	}
	return nil, errors.New("в подсети не осталось свободных адресов")
}
func (m *wgServer) Clients() []WgClient {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]WgClient, 0, len(m.d.Clients))
	for _, c := range m.d.Clients {
		x := *c
		x.Priv, x.Psk = "", ""
		out = append(out, x)
	}
	return out
}
func (m *wgServer) find(ip string) *WgClient {
	for _, c := range m.d.Clients {
		if c.IP == ip {
			return c
		}
	}
	return nil
}

// remapRoutes — клиенты сменили адреса (новая подсеть, правка файла): профили и свои правила переезжают за ними.
func remapRoutes(moved map[string]string) {
	if len(moved) == 0 {
		return
	}
	rtMu.Lock()
	cl, ov := map[string]string{}, map[string][]Rule{}
	for ip, p := range rt.Clients {
		if n, ok := moved[ip]; ok {
			ip = n
		}
		cl[ip] = p
	}
	for ip, r := range rt.Overrides {
		if n, ok := moved[ip]; ok {
			ip = n
		}
		ov[ip] = r
	}
	rt.Clients, rt.Overrides = cl, ov
	saveJSON("routes.json", rt)
	rtMu.Unlock()
}

// ---------------------------------------------------------------- резервные копии
func wgBackupDir() string { return filepath.Join(DataDir, "wg-backup") }
func (m *wgServer) backup(why string) {
	c := map[string]string{}
	for _, k := range wgKeys {
		c[k] = cfg(k, "\x00")
	}
	b := wgBackup{At: time.Now().Format("02.01.2006 15:04:05"), Why: why, D: m.d, Cfg: c, Conf: m.conf(false)}
	_ = os.MkdirAll(wgBackupDir(), 0o700)
	name := "wg-" + time.Now().Format("20060102-150405.000") + ".json"
	saveJSON(filepath.Join("wg-backup", name), b)
	files := m.backupFiles()
	for i := 30; i < len(files); i++ { // хранить последние 30
		_ = os.Remove(filepath.Join(wgBackupDir(), files[i]))
	}
}
func (m *wgServer) backupFiles() []string {
	var out []string
	es, _ := os.ReadDir(wgBackupDir())
	for _, e := range es {
		if strings.HasPrefix(e.Name(), "wg-") && strings.HasSuffix(e.Name(), ".json") {
			out = append(out, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out
}
func (m *wgServer) restore(file string) error {
	if filepath.Base(file) != file || !strings.HasPrefix(file, "wg-") {
		return errors.New("неверное имя копии")
	}
	var b wgBackup
	if !loadJSON(filepath.Join("wg-backup", file), &b) || b.D.Priv == "" {
		return errors.New("копия не читается")
	}
	m.backup("перед восстановлением копии от " + b.At)
	old := map[string]string{}
	for _, c := range m.d.Clients {
		old[c.Pub] = c.IP
	}
	moved := map[string]string{}
	for _, c := range b.D.Clients {
		if ip, ok := old[c.Pub]; ok && ip != c.IP {
			moved[ip] = c.IP
		}
	}
	m.d = b.D
	for k, v := range b.Cfg {
		if v == "\x00" {
			delCfg(k)
		} else {
			setCfg(k, v)
		}
	}
	remapRoutes(moved)
	m.save()
	m.restart("восстановлена копия конфигурации от " + b.At)
	return nil
}

// ---------------------------------------------------------------- правка файла целиком
var reKey = regexp.MustCompile(`^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$`)

func validKey(k string) bool {
	if !reKey.MatchString(k) {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(k)
	return err == nil && len(b) == 32
}

func maskLen(n *net.IPNet) int {
	if n == nil {
		return -1
	}
	o, _ := n.Mask.Size()
	return o
}

type wgPeer struct{ name, pub, psk, ip, extra string }

// parseServerConf — проверка и разбор конфигурации сервера; ошибки называют строку и что с ней не так.
func (m *wgServer) parseServerConf(text string) (priv, sub, port, mtu string, extra []string, peers []wgPeer, err error) {
	sec, comment := "", ""
	var cur *wgPeer
	seen := map[string]bool{}
	fail := func(n int, f string, a ...any) error {
		return fmt.Errorf("строка %d: %s", n, fmt.Sprintf(f, a...))
	}
	for i, raw := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		n, l := i+1, strings.TrimSpace(raw)
		switch {
		case l == "":
			continue
		case strings.HasPrefix(l, "#"):
			if sec == "Peer" && cur != nil && cur.pub == "" {
				cur.name = strings.TrimSpace(strings.TrimPrefix(l, "#"))
			}
			comment = l
			continue
		case strings.EqualFold(l, "[Interface]"):
			if seen["iface"] {
				return "", "", "", "", nil, nil, fail(n, "второй раздел [Interface]")
			}
			sec, seen["iface"] = "Interface", true
			continue
		case strings.EqualFold(l, "[Peer]"):
			sec = "Peer"
			peers = append(peers, wgPeer{})
			cur = &peers[len(peers)-1]
			continue
		}
		_ = comment
		k, v, ok := strings.Cut(l, "=")
		if !ok || sec == "" {
			return "", "", "", "", nil, nil, fail(n, "ожидалось «Параметр = значение» внутри [Interface] или [Peer]: %q", l)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if sec == "Interface" {
			switch strings.ToLower(k) {
			case "privatekey":
				if v != wgHidden && !validKey(v) {
					return "", "", "", "", nil, nil, fail(n, "PrivateKey — не ключ WireGuard (44 символа base64)")
				}
				priv = v
			case "address":
				ip, nw, e := net.ParseCIDR(v)
				if e != nil || ip.To4() == nil || maskLen(nw) != 24 || ip.To4()[3] != 1 {
					return "", "", "", "", nil, nil, fail(n, "Address должен быть вида 10.253.0.1/24 (адрес .1 в сети /24)")
				}
				sub = strings.TrimSuffix(ip.String(), ".1")
			case "listenport":
				if p, e := strconv.Atoi(v); e != nil || p < 1 || p > 65535 {
					return "", "", "", "", nil, nil, fail(n, "ListenPort — число от 1 до 65535")
				}
				port = v
			case "mtu":
				if p, e := strconv.Atoi(v); e != nil || p < 1280 || p > 1500 {
					return "", "", "", "", nil, nil, fail(n, "MTU — число от 1280 до 1500")
				}
				mtu = v
			case "saveconfig":
				return "", "", "", "", nil, nil, fail(n, "SaveConfig не поддерживается: файл ведёт VpnGuard")
			case "dns", "table", "preup", "postup", "predown", "postdown", "fwmark":
				extra = append(extra, k+" = "+v)
			default:
				return "", "", "", "", nil, nil, fail(n, "неизвестный параметр [Interface] %q (допустимы Address, ListenPort, PrivateKey, MTU, DNS, Table, FwMark, PreUp, PostUp, PreDown, PostDown)", k)
			}
			continue
		}
		switch strings.ToLower(k) {
		case "publickey":
			if !validKey(v) {
				return "", "", "", "", nil, nil, fail(n, "PublicKey — не ключ WireGuard")
			}
			cur.pub = v
		case "presharedkey":
			if v != wgHidden && !validKey(v) {
				return "", "", "", "", nil, nil, fail(n, "PresharedKey — не ключ WireGuard")
			}
			cur.psk = v
		case "allowedips":
			ip, nw, e := net.ParseCIDR(v)
			if e != nil || ip.To4() == nil || maskLen(nw) != 32 {
				return "", "", "", "", nil, nil, fail(n, "AllowedIPs клиента — один адрес вида 10.253.0.5/32")
			}
			cur.ip = ip.String()
		case "endpoint", "persistentkeepalive":
			if cur.extra != "" {
				cur.extra += "\n"
			}
			cur.extra += k + " = " + v
		default:
			return "", "", "", "", nil, nil, fail(n, "неизвестный параметр [Peer] %q (допустимы PublicKey, PresharedKey, AllowedIPs, Endpoint, PersistentKeepalive)", k)
		}
	}
	if !seen["iface"] {
		return "", "", "", "", nil, nil, errors.New("нет раздела [Interface]")
	}
	if priv == "" || sub == "" || port == "" {
		return "", "", "", "", nil, nil, errors.New("в [Interface] нужны PrivateKey, Address и ListenPort")
	}
	ips, pubs := map[string]int{}, map[string]int{}
	for i, p := range peers {
		if p.pub == "" || p.ip == "" {
			return "", "", "", "", nil, nil, fmt.Errorf("клиент №%d: нужны PublicKey и AllowedIPs", i+1)
		}
		if !strings.HasPrefix(p.ip, sub+".") || p.ip == sub+".1" {
			return "", "", "", "", nil, nil, fmt.Errorf("клиент «%s»: адрес %s вне подсети сервера %s.0/24", p.name, p.ip, sub)
		}
		if j, ok := ips[p.ip]; ok {
			return "", "", "", "", nil, nil, fmt.Errorf("клиенты №%d и №%d: одинаковый адрес %s", j+1, i+1, p.ip)
		}
		if j, ok := pubs[p.pub]; ok {
			return "", "", "", "", nil, nil, fmt.Errorf("клиенты №%d и №%d: одинаковый PublicKey", j+1, i+1)
		}
		ips[p.ip], pubs[p.pub] = i, i
	}
	return priv, sub, port, mtu, extra, peers, nil
}

// applyConf — сохранить проверенную конфигурацию: сервер, клиенты (по PublicKey), отключённые клиенты остаются как были.
func (m *wgServer) applyConf(text string) (string, error) {
	priv, sub, port, mtu, extra, peers, err := m.parseServerConf(text)
	if err != nil {
		return "", err
	}
	for _, c := range m.d.Clients {
		if c.Off {
			for _, p := range peers {
				if p.pub == c.Pub {
					return "", fmt.Errorf("клиент «%s» отключён — включите его на странице, а не в файле", c.Name)
				}
			}
		}
	}
	m.backup("перед правкой конфигурации сервера")
	if priv != wgHidden && priv != m.d.Priv {
		m.d.Priv, m.d.Pub = priv, key("pubkey", priv)
	}
	byPub := map[string]*WgClient{}
	for _, c := range m.d.Clients {
		byPub[c.Pub] = c
	}
	var list []*WgClient
	moved, added, removed := map[string]string{}, 0, []string{}
	kept := map[string]bool{}
	for i, p := range peers {
		c := byPub[p.pub]
		if c == nil || c.Off {
			name := p.name
			if name == "" {
				name = fmt.Sprintf("клиент %d", i+1)
			}
			c = &WgClient{Name: name, Pub: p.pub}
			added++
		}
		if c.IP != "" && c.IP != p.ip {
			moved[c.IP] = p.ip
		}
		c.IP, c.Extra = p.ip, p.extra
		if p.name != "" {
			c.Name = p.name
		}
		if p.psk != wgHidden {
			c.Psk = p.psk
		}
		kept[c.Pub] = true
		list = append(list, c)
	}
	for _, c := range m.d.Clients {
		switch {
		case c.Off:
			list = append(list, c)
		case !kept[c.Pub]:
			removed = append(removed, c.Name)
		}
	}
	m.d.Clients, m.d.Extra = list, extra
	setCfg("wg.subnet", sub)
	setCfg("wg.port", port)
	setCfg("wg.mtu", mtu)
	remapRoutes(moved)
	m.save()
	m.restart("конфигурация сервера изменена вручную")
	msg := fmt.Sprintf("Конфигурация сохранена: клиентов %d", len(peers))
	if added > 0 {
		msg += fmt.Sprintf(", новых %d (их конфигураций у шлюза нет)", added)
	}
	if len(removed) > 0 {
		msg += ", удалены: " + strings.Join(removed, ", ")
	}
	Decide("INFO", "WG-Server: %s", msg)
	return msg, nil
}

// ---------------------------------------------------------------- проверка и состояние
func (m *wgServer) Tick() {
	m.tk.Lock()
	defer m.tk.Unlock()
	m.ensure()
	if !active(m.unit()) {
		run("systemctl", "enable", "--now", m.unit())
		run("systemctl", "start", m.unit())
		Decide("WARN", "WG-Server: интерфейс %s не поднят → запуск", m.iface())
	}
	en, _ := run("systemctl", "is-enabled", m.unit())
	lp, _ := run("wg", "show", m.iface(), "listen-port")
	disk, _ := S.ReadFile(m.confPath())
	m.mu.Lock()
	m.svc = [3]string{strings.TrimSpace(en), strings.TrimSpace(lp), map[bool]string{true: "совпадает с настройками", false: "изменён не через VpnGuard"}[disk == m.conf(false)]}
	m.mu.Unlock()
	out, code := run("wg", "show", m.iface(), "dump")
	if code != 0 {
		m.setSt(2, false, "Не работает", strings.TrimSpace(out))
		return
	}
	by := map[string][]string{}
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Split(l, "\t"); len(f) >= 7 {
			by[f[0]] = f
		}
	}
	m.mu.Lock()
	on, rxAll := 0, 0.0
	for _, c := range m.d.Clients {
		c.On, c.Rx, c.Tx, c.Seen = false, 0, 0, "не подключался"
		f := by[c.Pub]
		if c.Off {
			c.Seen = "отключён"
		}
		if f == nil {
			continue
		}
		hs, _ := strconv.ParseInt(f[4], 10, 64)
		rx, _ := strconv.ParseFloat(f[5], 64)
		tx, _ := strconv.ParseFloat(f[6], 64)
		r := m.rates[c.IP]
		if r == nil {
			r = &[2]rate{}
			m.rates[c.IP] = r
		}
		c.Rx, c.Tx = r[0].bps(rx), r[1].bps(tx)
		if age := time.Now().Unix() - hs; hs > 0 {
			c.On = age < 180
			c.Seen = ago(age)
		}
		if c.On {
			on++
			rxAll += c.Tx
		}
	}
	n, pub, svc := len(m.d.Clients), m.d.Pub, m.svc
	m.mu.Unlock()
	m.metric("rx", rxAll)
	m.metric("clients", float64(on))
	lvl, why := 0, ""
	if svc[0] != "enabled" {
		lvl, why = 1, "служба не включена в автозапуск — после перезагрузки сервер не поднимется"
	} else if !strings.HasPrefix(svc[2], "совпадает") {
		lvl, why = 1, "файл "+m.confPath()+" изменён не через VpnGuard"
	}
	m.setSt(lvl, true, fmt.Sprintf("на связи %d из %d", on, n), why,
		[2]string{"Служба", m.unit() + " · работает · автозапуск: " + orDash(svc[0])},
		[2]string{"Слушает порт", "UDP " + orDash(svc[1])},
		[2]string{"Файл конфигурации", m.confPath() + " · " + svc[2]},
		[2]string{"Адрес сервера", m.subnet() + ".1/24"},
		[2]string{"Адрес для клиентов", m.endpoint()},
		[2]string{"Открытый ключ сервера", pub})
}
func ago(sec int64) string {
	switch {
	case sec < 120:
		return fmt.Sprintf("%d с назад", sec)
	case sec < 7200:
		return fmt.Sprintf("%d мин назад", sec/60)
	case sec < 172800:
		return fmt.Sprintf("%d ч назад", sec/3600)
	}
	return fmt.Sprintf("%d дн. назад", sec/86400)
}

// ---------------------------------------------------------------- настройки
func (m *wgServer) Fields() []Field {
	g1, g2 := "Сервер", "Для клиентов (попадает в их конфигурации)"
	return []Field{
		{Key: "wg.subnet", Title: "Подсеть (первые три числа)", Type: "text", Value: m.subnet(), Group: g1, Help: "Сервер получает .1, клиенты — .2 и дальше. При смене клиенты переезжают в новую подсеть с тем же последним числом"},
		{Key: "wg.port", Title: "UDP-порт", Type: "number", Value: cfg("wg.port", "51820"), Group: g1, Help: "Пробросьте его на роутере на этот компьютер"},
		{Key: "wg.mtu", Title: "MTU", Type: "number", Value: cfg("wg.mtu", "1420"), Group: g1, Help: "Пусто — автоматически. Адрес, порт и MTU применяются перезапуском сервера"},
		{Key: "wg.endpoint", Title: "Внешний адрес", Type: "text", Value: cfg("wg.endpoint", ""), Group: g2, Help: "Домен (DDNS) или внешний IP, можно с :портом, если на роутере проброшен другой"},
		{Key: "wg.dns", Title: "DNS", Type: "text", Value: cfg("wg.dns", "1.1.1.1"), Group: g2, Help: "Адреса через запятую. Адрес сервера подойдёт, только когда на шлюзе работает DNS"},
		{Key: "wg.allowed", Title: "Маршруты (AllowedIPs)", Type: "text", Value: cfg("wg.allowed", "0.0.0.0/0"), Group: g2, Help: "0.0.0.0/0 — весь трафик устройства через шлюз; или нужные сети через запятую"},
		{Key: "wg.keepalive", Title: "Keepalive, с", Type: "number", Value: cfg("wg.keepalive", "25"), Group: g2, Help: "0 — выключен"},
	}
}

var (
	reSubnet = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	reHost   = regexp.MustCompile(`^[A-Za-z0-9.\-]+(:\d{1,5})?$`)
)

func ipList(v string, cidr bool) error {
	for _, x := range strings.Split(v, ",") {
		x = strings.TrimSpace(x)
		if cidr {
			if _, _, err := net.ParseCIDR(x); err != nil {
				return fmt.Errorf("«%s» — не сеть вида 10.0.0.0/8", x)
			}
		} else if net.ParseIP(x) == nil {
			return fmt.Errorf("«%s» — не IP-адрес", x)
		}
	}
	return nil
}
func (m *wgServer) Set(k, v string) error {
	v = strings.TrimSpace(v)
	num := func(lo, hi int, what string) error {
		if n, err := strconv.Atoi(v); err != nil || n < lo || n > hi {
			return fmt.Errorf("%s — число от %d до %d", what, lo, hi)
		}
		return nil
	}
	var err error
	switch k {
	case "wg.subnet":
		if !reSubnet.MatchString(v) || net.ParseIP(v+".1") == nil {
			err = errors.New("подсеть задаётся тремя числами, например 10.253.0")
		}
	case "wg.port":
		err = num(1, 65535, "порт")
	case "wg.mtu":
		if v != "" {
			err = num(1280, 1500, "MTU")
		}
	case "wg.keepalive":
		err = num(0, 3600, "keepalive")
	case "wg.endpoint":
		if v != "" && !reHost.MatchString(v) {
			err = errors.New("внешний адрес — домен или IP, можно с :портом, без пробелов")
		}
	case "wg.dns":
		if v != "" {
			err = ipList(v, false)
		}
	case "wg.allowed":
		if v == "" {
			v = "0.0.0.0/0"
		}
		err = ipList(v, true)
	}
	if err != nil {
		return err
	}
	if v == cfg(k, "\x00") {
		return nil
	}
	m.tk.Lock()
	defer m.tk.Unlock()
	m.backup("перед изменением " + k)
	if k == "wg.subnet" {
		old, moved := m.subnet(), map[string]string{}
		for _, c := range m.d.Clients {
			n := v + strings.TrimPrefix(c.IP, old)
			moved[c.IP], c.IP = n, n
		}
		remapRoutes(moved)
	}
	setCfg(k, v)
	m.save()
	switch k {
	case "wg.subnet", "wg.port", "wg.mtu":
		m.restart("изменена настройка " + k)
		Decide("INFO", "WG-Server: %s = %s; конфигурации клиентов нужно загрузить на устройства заново", k, orDash(v))
	default:
		Decide("INFO", "WG-Server: %s = %s; конфигурации клиентов нужно загрузить на устройства заново (QR)", k, orDash(v))
	}
	return nil
}
func (m *wgServer) endpoint() string {
	ep := cfg("wg.endpoint", "")
	if ep == "" {
		return "не задан"
	}
	if !strings.Contains(ep, ":") {
		ep += ":" + cfg("wg.port", "51820")
	}
	return ep
}
func (m *wgServer) clientConf(c *WgClient) string {
	ep := m.endpoint()
	if ep == "не задан" {
		ep = "ВНЕШНИЙ_АДРЕС:" + cfg("wg.port", "51820")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s/32\n", c.Priv, c.IP)
	if d := cfg("wg.dns", "1.1.1.1"); d != "" {
		fmt.Fprintf(&b, "DNS = %s\n", d)
	}
	if mtu := cfg("wg.mtu", "1420"); mtu != "" {
		fmt.Fprintf(&b, "MTU = %s\n", mtu)
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\n", m.d.Pub)
	if c.Psk != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", c.Psk)
	}
	fmt.Fprintf(&b, "Endpoint = %s\nAllowedIPs = %s\n", ep, cfg("wg.allowed", "0.0.0.0/0"))
	if ka := cfg("wg.keepalive", "25"); ka != "" && ka != "0" {
		fmt.Fprintf(&b, "PersistentKeepalive = %s\n", ka)
	}
	return b.String()
}

// ---------------------------------------------------------------- действия
func (m *wgServer) Actions() []Action {
	return []Action{
		{ID: "add", Title: "+ Новый клиент", Args: []Field{{Key: "name", Title: "Имя устройства", Type: "text"}}},
		{ID: "showconf", Title: "Конфигурация сервера"},
		{ID: "editconf", Title: "Править конфигурацию сервера", Confirm: "Ключи скрыты — строки «(скрыт)» не меняйте. Перед сохранением файл проверяется, прежний попадает в резервные копии, сервер перезапускается.",
			Args: []Field{{Key: "text", Title: m.confPath(), Type: "code", Value: m.conf(true)}}},
		{ID: "restart", Title: "Перезапустить сервер", Confirm: "Все клиенты переподключатся. Перезапустить?"},
		{ID: "fixsvc", Title: "Починить службу", Confirm: "Записать файл конфигурации заново, включить автозапуск " + m.unit() + " и перезапустить? Клиенты переподключатся."},
		{ID: "regen", Title: "Сменить ключ сервера", Danger: true, Confirm: "Сменить ключ сервера? Старые конфигурации на ВСЕХ устройствах перестанут подключаться — их нужно будет загрузить заново (QR). Сервер перезапустится."},
		{ID: "recreate", Title: "Создать сервер заново", Danger: true, Confirm: "Новые ключи, ВСЕ клиенты удаляются — их придётся создать и настроить на устройствах заново. Прежняя конфигурация останется в резервных копиях.",
			Args: []Field{{Key: "word", Title: "Для подтверждения введите слово ЗАНОВО", Type: "text"}}},
	}
}
func (m *wgServer) Do(id string, a map[string]string) (string, error) {
	m.tk.Lock()
	defer m.tk.Unlock()
	switch id {
	case "add":
		n, err := m.add(a["name"])
		if err != nil {
			return "", err
		}
		m.viewIP, m.viewSrv = n.IP, false
		Decide("INFO", "WG-Server: создан клиент %s (%s)", n.Name, n.IP)
		return "Клиент " + n.Name + " создан (" + n.IP + "), QR и конфигурация — ниже", nil
	case "restart":
		run("systemctl", "restart", m.unit())
		return "Сервер перезапущен", nil
	case "showconf":
		m.viewSrv, m.viewIP = !m.viewSrv, ""
		return map[bool]string{true: "Конфигурация сервера показана ниже", false: "Конфигурация скрыта"}[m.viewSrv], nil
	case "editconf":
		return m.applyConf(a["text"])
	case "fixsvc":
		m.save()
		run("systemctl", "enable", m.unit())
		m.restart("починка службы")
		return "Файл записан, автозапуск включён, сервер перезапущен", nil
	case "regen":
		m.backup("перед сменой ключа сервера")
		m.d.Priv = key("genkey", "")
		m.d.Pub = key("pubkey", m.d.Priv)
		m.save()
		m.restart("ключ сервера сменён")
		return "Новый ключ сервера. Конфигурации клиентов обновились — загрузите их на устройства заново (QR)", nil
	case "recreate":
		if strings.ToUpper(strings.TrimSpace(a["word"])) != "ЗАНОВО" {
			return "", errors.New("не подтверждено: нужно ввести слово ЗАНОВО")
		}
		m.backup("перед созданием сервера заново")
		n := len(m.d.Clients)
		m.d = wgData{Priv: key("genkey", "")}
		m.d.Pub = key("pubkey", m.d.Priv)
		m.viewIP, m.viewSrv = "", false
		m.save()
		m.restart("сервер создан заново")
		Decide("WARN", "WG-Server: сервер создан заново, удалено клиентов: %d (копия — в резервных копиях)", n)
		return fmt.Sprintf("Сервер создан заново, удалено клиентов: %d", n), nil
	case "restore":
		if err := m.restore(a["row"]); err != nil {
			return "", err
		}
		return "Конфигурация восстановлена, сервер перезапущен", nil
	}
	c := m.find(a["row"])
	if c == nil {
		return "", errors.New("клиент не найден")
	}
	switch id {
	case "config":
		if c.Priv == "" {
			return "", errors.New("конфигурации этого клиента у шлюза нет: он добавлен правкой файла, его ключ хранится только на устройстве")
		}
		if m.viewIP == c.IP {
			m.viewIP = ""
			return "Конфигурация скрыта", nil
		}
		m.viewIP, m.viewSrv = c.IP, false
		return "QR и конфигурация показаны ниже", nil
	case "toggle":
		c.Off = !c.Off
		m.save()
		if c.Off {
			return c.Name + " отключён", nil
		}
		return c.Name + " включён", nil
	case "rename":
		nm := strings.TrimSpace(a["name"])
		if nm == "" {
			return "", errors.New("введите имя")
		}
		for _, x := range m.d.Clients {
			if x != c && strings.EqualFold(x.Name, nm) {
				return "", errors.New("клиент с таким именем уже есть")
			}
		}
		c.Name = nm
		m.save()
		return "Клиент переименован", nil
	case "delete":
		for i, x := range m.d.Clients {
			if x == c {
				m.d.Clients = append(m.d.Clients[:i], m.d.Clients[i+1:]...)
				break
			}
		}
		if m.viewIP == c.IP {
			m.viewIP = ""
		}
		m.save()
		Decide("INFO", "WG-Server: клиент %s (%s) удалён", c.Name, c.IP)
		return "Клиент " + c.Name + " удалён", nil
	}
	return "", errors.New("неизвестное действие")
}
func fileName(s string) string {
	s = regexp.MustCompile(`[^\p{L}\p{N}_.-]+`).ReplaceAllString(s, "_")
	if s == "" {
		s = "client"
	}
	return s + ".conf"
}
func (m *wgServer) Tables() []Table {
	var rows [][]string
	for _, c := range m.Clients() {
		st := "не на связи"
		if c.Off {
			st = "отключён"
		} else if c.On {
			st = "на связи"
		}
		rows = append(rows, []string{c.IP, c.Name, st, c.Seen, fmtRate(c.Tx)})
	}
	var t []Table
	if c := m.find(m.viewIP); c != nil && c.Priv != "" {
		cf := m.clientConf(c)
		t = append(t, Table{Title: "Клиент «" + c.Name + "»: QR и конфигурация", Img: qrImage(cf), Text: cf, File: fileName(c.Name), Top: true,
			Note: "Приложение WireGuard: «+» → «Сканировать QR-код». В конфигурации закрытый ключ клиента — никому не пересылайте."})
	}
	if m.viewSrv {
		t = append(t, Table{Title: "Конфигурация сервера", Text: m.conf(true), Note: m.confPath() + " · ключи скрыты", Top: true})
	}
	t = append(t, Table{Title: "Клиенты", Cols: []string{"Адрес", "Имя", "Состояние", "Рукопожатие", "Скорость ↓"}, Rows: rows, Empty: "Клиентов нет — создайте первого",
		Actions: []Action{{ID: "config", Title: "QR и конфигурация"}, {ID: "toggle", Title: "Вкл/выкл"},
			{ID: "rename", Title: "Переименовать", Args: []Field{{Key: "name", Title: "Новое имя", Type: "text"}}},
			{ID: "delete", Title: "Удалить", Danger: true, Confirm: "Удалить клиента? Его конфигурация перестанет работать."}}})
	var bk [][]string
	for _, f := range m.backupFiles() {
		var b wgBackup
		if loadJSON(filepath.Join("wg-backup", f), &b) {
			sub := b.Cfg["wg.subnet"]
			if sub == "\x00" {
				sub = "10.253.0"
			}
			port := b.Cfg["wg.port"]
			if port == "\x00" {
				port = "51820"
			}
			bk = append(bk, []string{f, b.At, b.Why, sub + ".1/24 · UDP " + port, strconv.Itoa(len(b.D.Clients))})
		}
	}
	t = append(t, Table{Title: "Резервные копии конфигурации", Cols: []string{"Файл", "Когда", "Перед чем", "Сервер", "Клиентов"}, Rows: bk,
		Empty: "Копий пока нет — они делаются перед каждым изменением сервера", Note: "Хранятся последние 30. Восстановление перезапускает сервер; текущая конфигурация тоже попадёт в копии.",
		Actions: []Action{{ID: "restore", Title: "Восстановить", Confirm: "Вернуть сервер и клиентов к этой копии? Сервер перезапустится."}}})
	return t
}
func fmtRate(bps float64) string {
	if bps >= 1e6 {
		return fmt.Sprintf("%.1f Мбит/с", bps/1e6)
	}
	return fmt.Sprintf("%.0f кбит/с", bps/1e3)
}
func (m *wgServer) Checks() []Check {
	return []Check{{ID: "wg.unit", Title: "Интерфейс WG-Server поднят", FixTitle: "Перезапустить",
		Run: func() Finding { return Finding{OK: active(m.unit()), Text: m.unit()} },
		Fix: func() (string, error) {
			run("systemctl", "restart", m.unit())
			return "сервер перезапущен", nil
		}},
		{ID: "wg.enabled", Title: "WG-Server запускается при загрузке", FixTitle: "Включить автозапуск",
			Run: func() Finding {
				o, _ := run("systemctl", "is-enabled", m.unit())
				return Finding{OK: strings.TrimSpace(o) == "enabled", Text: "systemctl is-enabled " + m.unit() + ": " + strings.TrimSpace(o), Hint: "Без автозапуска после перезагрузки клиенты не подключатся"}
			},
			Fix: func() (string, error) {
				run("systemctl", "enable", m.unit())
				return "автозапуск включён", nil
			}},
		{ID: "wg.file", Title: "Файл конфигурации сервера — от VpnGuard", FixTitle: "Записать заново",
			Run: func() Finding {
				disk, _ := S.ReadFile(m.confPath())
				return Finding{OK: disk == m.conf(false), Text: m.confPath(), Hint: "Файл изменили в обход VpnGuard. Правьте конфигурацию на вкладке WG-Server; «Записать заново» вернёт файл к настройкам VpnGuard"}
			},
			Fix: func() (string, error) {
				m.save()
				m.restart("файл записан заново")
				return "файл записан, сервер перезапущен", nil
			}},
		{ID: "wg.endpoint", Title: "Задан внешний адрес для клиентов",
			Run: func() Finding {
				return Finding{OK: cfg("wg.endpoint", "") != "", Text: "настройка «Внешний адрес»", Hint: "Укажите домен или внешний IP на вкладке WG-Server и пробросьте UDP-порт на роутере"}
			}}}
}
