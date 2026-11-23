// Режим имитации (--sim): модель Ubuntu-шлюза, которая отвечает на те же команды, что и настоящая система.
// Модули работают тем же кодом, что и в бою; меняется только Sys. Сбои включаются из веба (вкладка «Диагностика»).
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type simSys struct {
	mu       sync.Mutex
	files    map[string]string
	fault    map[string]bool
	units    map[string]bool
	mdzConn  bool
	mdzProto string
	mdzSvc   string
	mdzAcct  string
	devices  []string
	bytes    map[string]float64
	at       map[string]time.Time
}

var simFaults = [][2]string{
	{"inet", "Провайдер: нет интернета"},
	{"meduza.server", "MeduzaVPN: протокол ULTRA заблокирован провайдером"},
	{"meduza.daemon", "MeduzaVPN: служба meduzavpnd упала"},
	{"meduza.login", "MeduzaVPN: вход в аккаунт слетел"},
	{"awg.server", "AmneziaWG: сервер не отвечает"},
	{"zapret.dpi", "zapret2: провайдер сменил блокировку, стратегия перестала работать"},
}

func newSim() *simSys {
	s := &simSys{files: map[string]string{}, fault: map[string]bool{}, bytes: map[string]float64{}, at: map[string]time.Time{},
		units: map[string]bool{"meduzavpnd": true, "awg-quick@awg0": true, "wg-quick@wg_server": true}, mdzConn: true, mdzProto: "ultra", mdzSvc: "nl-1",
		mdzAcct: "user@example.com", devices: []string{"101", "102", "103"}}
	s.files["/etc/amnezia/amneziawg/awg0.conf"] = "[Interface]\nPrivateKey = " + simKey() + "\nAddress = 10.8.1.2/32\nTable = off\nJc = 4\nJmin = 40\nJmax = 70\n\n[Peer]\nPublicKey = " + simKey() + "\nEndpoint = 203.0.113.20:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
	s.files["/etc/amnezia/amneziawg/awg-fi.conf"] = "[Interface]\nPrivateKey = " + simKey() + "\nAddress = 10.8.2.2/32\nTable = off\n\n[Peer]\nPublicKey = " + simKey() + "\nEndpoint = 198.51.100.7:443\nAllowedIPs = 0.0.0.0/0\n"
	return s
}
func simKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
func (s *simSys) SetFault(k string, on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fault[k] = on
	if k == "meduza.daemon" && on {
		s.units["meduzavpnd"], s.mdzConn = false, false
	}
	if k == "meduza.login" && on {
		s.mdzConn = false
	}
}
func (s *simSys) Faults() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]bool{}
	for k, v := range s.fault {
		out[k] = v
	}
	return out
}

// Stream: вход по QR в имитации — ссылка сразу, «подтверждение на телефоне» через 12 секунд.
func (s *simSys) Stream(t time.Duration, stdin string, line func(string), name string, a ...string) int {
	if name == "meduzavpn" && len(a) > 1 && a[0] == "login" && a[1] == "--qr" {
		s.mu.Lock()
		up := s.units["meduzavpnd"]
		s.mu.Unlock()
		if !up {
			line("the MeduzaVPN daemon is not running: start it with `sudo systemctl start meduzavpnd`")
			return 3
		}
		line(`{"verify_url":"https://meduzavpn.com/link/K7Q2-M9XD","user_code":"K7Q2-M9XD","expires_in":300,"interval":3}`)
		line("█▀▀▀▀▀█ ▄▀ █▀▀▀▀▀█")
		time.Sleep(simLoginWait)
		s.mu.Lock()
		s.fault["meduza.login"] = false
		s.mu.Unlock()
		line("Approved.")
		return 0
	}
	out, code := s.Run(t, stdin, name, a...)
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		line(l)
	}
	return code
}

var (
	simLoginWait = 12 * time.Second
	simHosts     = map[string]string{"nl-1": "185.10.20.30", "de-2": "91.200.14.7", "fi-1": "95.216.3.44"}
)

// grow — счётчик байт, растущий со скоростью bps (с небольшим разбросом).
func (s *simSys) grow(key string, bps float64) float64 {
	now := time.Now()
	if t, ok := s.at[key]; ok {
		j := 0.7 + float64(now.UnixNano()/1e6%600)/1000
		s.bytes[key] += bps / 8 * now.Sub(t).Seconds() * j
	}
	s.at[key] = now
	return s.bytes[key]
}
func (s *simSys) ifaceOK(iface string) bool {
	switch {
	case s.fault["inet"]:
		return false
	case iface == "mdz0":
		return s.units["meduzavpnd"] && s.mdzConn && !(s.fault["meduza.server"] && s.mdzProto == "ultra")
	case mod("wg-out-"+iface) != nil || mod("olcrtc-out-"+iface) != nil:
		return true
	case iface == "eth0":
		return true
	default:
		return s.units["awg-quick@"+iface] && !s.fault["awg.server"]
	}
}
func (s *simSys) zapretOK() bool {
	a := s.files["/etc/vpnguard/nfqws2.args"]
	if !s.units["vpnguard-nfqws2"] {
		return false
	}
	if s.fault["zapret.dpi"] {
		return strings.Contains(a, "hostfakesplit")
	}
	return strings.Contains(a, "multisplit")
}

var reBlocked = regexp.MustCompile(`youtube|googlevideo|ytimg|discord`)

func (s *simSys) Run(_ time.Duration, stdin, name string, a ...string) (string, int) {
	if name == "env" && len(a) >= 2 && a[0] == "LC_ALL=C" {
		return s.Run(6*time.Second, stdin, a[1], a[2:]...)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	arg := func(i int) string {
		if i < len(a) {
			return a[i]
		}
		return ""
	}
	after := func(flag string) string {
		for i, x := range a {
			if x == flag {
				return arg(i + 1)
			}
		}
		return ""
	}
	switch name {
	case "systemctl":
		u := arg(1)
		switch arg(0) {
		case "is-enabled":
			return "enabled\n", 0
		case "is-active":
			if s.units[u] {
				return "active\n", 0
			}
			return "inactive\n", 3
		case "start", "restart":
			s.units[u] = true
			if u == "meduzavpnd" {
				s.fault["meduza.daemon"], s.mdzConn = false, false
			}
		case "stop":
			s.units[u] = false
			if u == "meduzavpnd" {
				s.mdzConn = false
			}
		}
		return "", 0
	case "meduzavpn":
		if !s.units["meduzavpnd"] {
			return "no daemon: meduzavpnd is not running\n", 3
		}
		switch arg(0) {
		case "status":
			signed := !s.fault["meduza.login"]
			acct := ""
			if signed {
				acct = s.mdzAcct
			}
			names := map[string]string{"nl-1": "Нидерланды", "de-2": "Германия", "fi-1": "Финляндия"}
			rx := 0.0
			if s.mdzConn {
				rx = 4e6
			}
			return fmt.Sprintf(`{"daemon_running":true,"signed_in":%v,"signed_in_as":"%s","connected":%v,"protocol":"%s","service":"%s","service_name":"%s","interface":"mdz0","endpoint":"%s:443","rx_bytes":%.0f,"tx_bytes":%.0f,"since_unix":%d,"date_renews":"2027-01-15"}`,
				signed, acct, s.mdzConn, s.mdzProto, s.mdzSvc, names[s.mdzSvc], simHosts[s.mdzSvc], s.grow("mdz.rx", rx), s.grow("mdz.tx", rx/10), time.Now().Add(-47*time.Minute).Unix()), 0
		case "version":
			return "meduzavpn 1.2.79+355\ndaemon 1.2.79+355, control protocol 3\n", 0
		case "logout":
			s.fault["meduza.login"], s.mdzConn = true, false
			return "Signed out.\n", 0
		case "profile":
			if s.fault["meduza.login"] {
				return "not signed in (run `meduzavpn login`)\n", 2
			}
			h := simHosts[after("--service")]
			switch after("--service") {
			case "nl-1":
				return "[Interface]\nPrivateKey = (имитация)\nAddress = 10.66.0.2/32\n\n[Peer]\nPublicKey = x\nEndpoint = " + h + ":51820\nAllowedIPs = 0.0.0.0/0\n", 0
			case "de-2":
				return "vless://0f6c1a2e-1111-2222-3333-444455556666@" + h + ":443?security=reality&type=tcp#de-2\n", 0
			case "fi-1":
				return "client\ndev tun\nremote " + h + " 1194\n", 0
			}
			return "unknown service\n", 1
		case "devices":
			if s.fault["meduza.login"] {
				return "not signed in\n", 2
			}
			all := map[string]string{"101": `{"id":101,"device_name":"gw","platform":"linux","app_version":"1.2.79","ip":"203.0.113.5","login_method":"qr","last_seen_at":"сейчас","current":true}`,
				"102": `{"id":102,"device_name":"Pixel 8","platform":"android","app_version":"1.2.80","ip":"203.0.113.9","login_method":"password","last_seen_at":"вчера"}`,
				"103": `{"id":103,"device_name":"MacBook","platform":"macos","app_version":"1.2.77","ip":"198.51.100.4","login_method":"password","last_seen_at":"12.10.2026"}`}
			switch arg(1) {
			case "revoke":
				var keep []string
				for _, d := range s.devices {
					if d != arg(2) {
						keep = append(keep, d)
					}
				}
				s.devices = keep
				return "ok\n", 0
			case "revoke-others":
				s.devices = []string{"101"}
				return "ok\n", 0
			}
			var rows []string
			for _, d := range s.devices {
				rows = append(rows, all[d])
			}
			return `{"devices":[` + strings.Join(rows, ",") + `]}`, 0
		case "config":
			conf := map[string]any{}
			_ = json.Unmarshal([]byte(s.files[mdzConfPath]), &conf)
			switch arg(1) {
			case "set":
				k := arg(2)
				switch {
				case k == "exclude_routes" || k == "routes" || k == "dns":
					conf[k] = a[3:]
				case arg(3) == "true" || arg(3) == "false":
					conf[k] = arg(3) == "true"
				default:
					conf[k] = arg(3)
				}
			case "unset":
				delete(conf, arg(2))
			}
			b, _ := json.MarshalIndent(conf, "", "  ")
			s.files[mdzConfPath] = string(b)
			return "", 0
		case "list":
			if s.fault["meduza.login"] {
				return "not signed in\n", 2
			}
			if arg(1) == "--protocols" {
				return `{"protocols":[{"id":"ultra","name":"ULTRA"},{"id":"vless2","name":"VLESS Reality"},{"id":"wireguard","name":"WireGuard"},{"id":"openvpn","name":"OpenVPN"}]}`, 0
			}
			return `{"services":[{"id":"nl-1","name":"Нидерланды","country":"NL"},{"id":"de-2","name":"Германия","country":"DE"},{"id":"fi-1","name":"Финляндия","country":"FI"}]}`, 0
		case "connect":
			if s.fault["meduza.login"] {
				return "not signed in\n", 2
			}
			if p := after("--protocol"); p != "" {
				s.mdzProto = p
			}
			if len(a) > 1 && !strings.HasPrefix(a[1], "--") {
				s.mdzSvc = a[1]
			}
			s.mdzConn = true
			return "connected\n", 0
		case "disconnect":
			s.mdzConn = false
			return "disconnected\n", 0
		case "login":
			if strings.TrimSpace(stdin) == "wrong" {
				return "invalid email or password\n", 1
			}
			s.fault["meduza.login"] = false
			s.mdzAcct = after("--email")
			return "Signed in.\n", 0
		}
	case "ping":
		h := arg(len(a) - 1)
		count := after("-c")
		if count == "" {
			count = "3"
		}
		if s.fault["inet"] || h == simHosts["fi-1"] { // финский сервер не отвечает на ICMP — пинг по TCP
			return "--- " + h + " ping statistics ---\n" + count + " packets transmitted, 0 received, 100% packet loss\n", 1
		}
		ms := map[string]float64{simHosts["nl-1"]: 38.4, simHosts["de-2"]: 51.9}[h]
		if ms == 0 {
			ms = 70
		}
		var replies string
		if after("-c") == "5" {
			for i := 1; i <= 5; i++ {
				replies += fmt.Sprintf("64 bytes from %s: icmp_seq=%d ttl=64 time=%.1f ms\n", h, i, ms+float64(i%2))
			}
		}
		return replies + fmt.Sprintf("--- %s ping statistics ---\n%s packets transmitted, %s received, 0%% packet loss\nrtt min/avg/max/mdev = %.1f/%.1f/%.1f/1.2 ms\n", h, count, count, ms-2, ms, ms+3), 0
	case "nft":
		if arg(0) == "-j" {
			return `{"nftables":[{"rule":{"family":"inet","table":"vpnguard","chain":"classify","comment":"p1_r1","expr":[{"counter":{"packets":12,"bytes":840}}]}}]}`, 0
		}
	case "dpkg":
		if arg(0) == "--print-architecture" {
			return "amd64\n", 0
		}
		return "(имитация) пакет установлен\n", 0
	case "sha256sum":
		return "0000  " + arg(0) + "\n", 0
	case "curl":
		if u := arg(len(a) - 1); strings.HasSuffix(u, "release.json") {
			return `{"version":"1.2.80+360","files":[{"key":"meduzavpn_amd64.deb","version":"1.2.80+360","sha256":"0000","url":"https://example.invalid/meduzavpn_amd64.deb"}]}`, 0
		}
		if after("-w") == "%{time_connect}" {
			if s.fault["inet"] {
				return "0.000", 28
			}
			return "0.061", 0
		}
		iface, url := after("--interface"), arg(len(a)-1)
		if iface == "192.168.1.50" {
			iface = "eth0"
		}
		ok := s.ifaceOK(iface)
		if ok && iface == "eth0" && reBlocked.MatchString(url) {
			ok = s.zapretOK()
		}
		if ok {
			if strings.Contains(url, "report_mapping") {
				return "provider mapping sn-simulated", 0
			}
			if after("-w") == "" && strings.Contains(url, "youtube.com") {
				return `<script src="/s/player/simulated/player_ias.vflset/en_US/base.js"></script>`, 0
			}
			if strings.Contains(after("-w"), "size_download") {
				if strings.Contains(url, "/base.js") {
					return "200 1048576 1.0 0.05 0.1", 0
				}
				return "200 0 0.092 0.05 0.08", 0
			}
			if iface == "mdz0" && s.mdzProto != "ultra" {
				return "200 0.184", 0
			}
			return "200 0.092", 0
		}
		return "000 6.0", 28
	case "ip":
		if arg(0) == "route" && arg(1) == "get" {
			return "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.50 uid 0\n", 0
		}
		if arg(0) == "-4" && arg(2) == "addr" {
			return "2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0\n", 0
		}
		if arg(1) == "link" {
			i := arg(3)
			if i == "eth0" || i == "wg_server" || (i == "mdz0" && s.mdzConn) || s.units["awg-quick@"+i] {
				return "2: " + i + ": <UP,LOWER_UP>\n", 0
			}
			return "Device \"" + i + "\" does not exist.\n", 1
		}
	case "awg":
		i := arg(1)
		if !s.units["awg-quick@"+i] {
			return "Unable to access interface: No such device\n", 1
		}
		if arg(2) == "latest-handshakes" {
			t := time.Now().Unix() - 25
			if s.fault["awg.server"] || s.fault["inet"] {
				t -= 900
			}
			return fmt.Sprintf("PEER\t%d\n", t), 0
		}
		v := 0.0
		if s.ifaceOK(i) {
			v = 1.5e6
		}
		return fmt.Sprintf("PEER\t%.0f\t%.0f\n", s.grow("awg.rx", v), s.grow("awg.tx", v/8)), 0
	case "wg":
		switch arg(0) {
		case "genkey", "genpsk":
			return simKey() + "\n", 0
		case "pubkey":
			h := sha256.Sum256([]byte(strings.TrimSpace(stdin)))
			return base64.StdEncoding.EncodeToString(h[:]) + "\n", 0
		case "show":
			if arg(2) == "peers" && mod("wg-out-"+arg(1)) != nil {
				return "simulated-peer\n", 0
			}
			if arg(2) == "listen-port" {
				return confVal(s.files["/etc/wireguard/"+arg(1)+".conf"], "ListenPort") + "\n", 0
			}
			out := "PRIV\tPUB\t51820\toff\n"
			conf := s.files["/etc/wireguard/"+arg(1)+".conf"]
			for i, blk := range strings.Split(conf, "[Peer]")[1:] {
				pub, ip := confVal(blk, "PublicKey"), strings.TrimSuffix(confVal(blk, "AllowedIPs"), "/32")
				hs, bps := time.Now().Unix()-int64(10+i*7), float64(300000*(i+1))
				if i%4 == 2 {
					hs, bps = time.Now().Unix()-3*86400, 0
				}
				out += fmt.Sprintf("%s\tPSK\t192.0.2.%d:5%04d\t%s/32\t%d\t%.0f\t%.0f\t25\n", pub, 10+i, i, ip, hs, s.grow("wg.rx."+ip, bps/6), s.grow("wg.tx."+ip, bps))
			}
			return out, 0
		}
	case "sysctl":
		return "1\n", 0
	case "timedatectl":
		return "yes\n", 0
	case "df":
		return "Filesystem Use%\n/dev/sda2 37%\n", 0
	case "journalctl":
		return time.Now().Format("Jan 02 15:04:05") + " gw " + arg(1) + "[812]: (имитация) служба работает штатно\n", 0
	}
	return "", 0
}
func confVal(text, key string) string {
	m := regexp.MustCompile(`(?mi)^\s*` + key + `\s*=\s*(.+?)\s*$`).FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}
func (s *simSys) ReadFile(p string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.files[p]; ok {
		return v, nil
	}
	if name, ok := strings.CutPrefix(p, "/sys/class/net/"); ok {
		if iface, ok := strings.CutSuffix(name, "/tun_flags"); ok && mod("olcrtc-out-"+iface) != nil {
			return "0x1001", nil
		}
	}
	return "", os.ErrNotExist
}
func (s *simSys) WriteFile(p, t string, _ os.FileMode) error {
	s.mu.Lock()
	s.files[p] = t
	s.mu.Unlock()
	return nil
}
func (s *simSys) Remove(p string) error { s.mu.Lock(); delete(s.files, p); s.mu.Unlock(); return nil }
func (s *simSys) List(dir string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	pre := strings.TrimSuffix(dir, "/") + "/"
	for p := range s.files {
		if strings.HasPrefix(p, pre) && !strings.Contains(p[len(pre):], "/") {
			out = append(out, p[len(pre):])
		}
	}
	sort.Strings(out)
	return out
}

// В имитации домены превращаются в постоянные «адреса» из тестового диапазона.
func (s *simSys) Resolve(h string) []string {
	x := sha256.Sum256([]byte(h))
	return []string{fmt.Sprintf("198.18.%d.%d", x[0], x[1])}
}
