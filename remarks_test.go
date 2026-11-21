package main

import (
	"strings"
	"testing"
	"time"
)

// Замечания пользователя к этапу 1: MeduzaVPN, WG-Server, вкладка «Интернет». Всё — на имитации.

func TestMeduzaLoginQRAndPassword(t *testing.T) {
	setup(t)
	previousWait := simLoginWait
	t.Cleanup(func() { simLoginWait = previousWait })
	simLoginWait = 300 * time.Millisecond
	m := mod("meduza").(*meduza)
	// Пинги проверяются отдельно; здесь они не должны пережить временную папку теста.
	m.pingRun.Lock()
	t.Cleanup(func() { m.loginWork.Wait(); m.pingRun.Unlock() })
	m.cli("logout")
	m.Tick()
	if m.signed || m.Status().State != "Не выполнен вход" {
		t.Fatalf("после выхода ожидался «Не выполнен вход», получено %q", m.Status().State)
	}
	hasAct := func(id string) bool {
		for _, a := range m.Actions() {
			if a.ID == id {
				return true
			}
		}
		return false
	}
	if !hasAct("login") || !hasAct("loginpw") || hasAct("logout") {
		t.Fatal("без входа должны быть кнопки входа по QR и по паролю, без кнопки выхода")
	}
	if _, err := m.loginQR(); err != nil {
		t.Fatal(err)
	}
	tb := m.Tables()
	if !tb[0].Top || !strings.HasPrefix(tb[0].Img, "data:image/svg+xml;base64,") || !strings.Contains(tb[0].Text, "K7Q2-M9XD") {
		t.Fatalf("ожидался QR-код картинкой наверху страницы: %+v", tb[0])
	}
	m.loginWork.Wait()
	if !m.signed || m.account == "" {
		t.Fatal("после подтверждения на телефоне вход должен выполниться")
	}
	// по паролю: неверный пароль — понятная ошибка, верный — вход; пароль не попадает в журнал
	m.cli("logout")
	m.readStatus()
	if _, err := m.loginPassword("user@example.com", "wrong"); err == nil {
		t.Error("неверный пароль должен давать ошибку")
	}
	if _, err := m.loginPassword("не почта", "x"); err == nil {
		t.Error("неверный адрес почты должен отклоняться до запуска CLI")
	}
	if _, err := m.loginPassword("me@example.com", "s3cret-Pass"); err != nil {
		t.Fatal(err)
	}
	m.loginWork.Wait()
	for _, l := range snapshotLog(&logRing) {
		if strings.Contains(l.Text, "s3cret-Pass") {
			t.Fatal("пароль попал в журнал")
		}
	}
	m.readStatus()
	if !m.signed || m.account != "me@example.com" {
		t.Errorf("ожидался вход как me@example.com, получено %q", m.account)
	}
}

func TestMeduzaPingAndProfiles(t *testing.T) {
	setup(t)
	for in, want := range map[string]string{
		"[Peer]\nEndpoint = 1.2.3.4:51820\n":               "1.2.3.4:51820",
		"vless://uuid@example.org:443?security=reality#x":  "example.org:443",
		"client\nremote 5.6.7.8 1194\n":                    "5.6.7.8:1194",
		"server: hy.example.org:8443\nauth: x\n":           "hy.example.org:8443",
		`{"config_text":"[Peer]\nEndpoint = 9.9.9.9:1\n"}`: "9.9.9.9:1",
		"vless://uuid@[2001:db8::1]:443?x":                 "[2001:db8::1]:443",
	} {
		if got := profileHost(in); got != want {
			t.Errorf("profileHost(%q) = %q, ожидалось %q", in, got, want)
		}
	}
	m := mod("meduza").(*meduza)
	m.catalog(true)
	m.pingRun.Lock()
	m.pingRun.Unlock()
	if got := m.pingText("nl-1"); got != "38 мс" {
		t.Errorf("пинг nl-1 по ICMP: %q", got)
	}
	if got := m.pingText("fi-1"); got != "61 мс" {
		t.Errorf("fi-1 не отвечает на ICMP — ожидался пинг по TCP 61 мс, получено %q", got)
	}
	var opt string
	for _, f := range m.Fields() {
		if f.Key == "meduza.serviceId" {
			for _, o := range f.Options {
				if o.V == "de-2" {
					opt = o.T
				}
			}
		}
	}
	if !strings.Contains(opt, "52 мс") {
		t.Errorf("пинг должен быть виден при выборе страны: %q", opt)
	}
}

func TestMeduzaDaemonSettingsAndDevices(t *testing.T) {
	setup(t)
	m := mod("meduza").(*meduza)
	if err := m.Set("meduza.cfg.exclude_routes", "192.168.1.0/24, 10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	if err := m.Set("meduza.cfg.kill_switch", "false"); err != nil {
		t.Fatal(err)
	}
	if got := m.daemonVal("exclude_routes"); got != "192.168.1.0/24, 10.0.0.0/8" {
		t.Errorf("exclude_routes: %q", got)
	}
	if m.Set("meduza.cfg.exclude_routes", "не сеть") == nil || m.Set("meduza.cfg.mtu", "100") == nil {
		t.Error("неверные значения настроек службы должны отклоняться")
	}
	for _, c := range m.Checks() {
		if c.ID == "meduza.killswitch" && !c.Run().OK {
			t.Error("kill switch выключен — проверка должна проходить")
		}
	}
	m.readDevices()
	if len(m.devices) != 3 {
		t.Fatalf("ожидалось 3 устройства, получено %d", len(m.devices))
	}
	if _, err := m.Do("revoke", map[string]string{"row": "101"}); err == nil {
		t.Error("сам шлюз нельзя отключить как чужое устройство")
	}
	if _, err := m.Do("revoke", map[string]string{"row": "103"}); err != nil || len(m.devices) != 2 {
		t.Errorf("отключение устройства: %v, осталось %d", err, len(m.devices))
	}
	m.checkVersion(true)
	if m.ver != "1.2.79+355" || m.remote != "1.2.80+360" || !verLess(m.ver, m.remote) {
		t.Errorf("версии: установлена %q, доступна %q", m.ver, m.remote)
	}
}

func TestWgServerConfigEditBackupRestore(t *testing.T) {
	setup(t)
	w := wgMod
	n0 := len(w.d.Clients)
	shown := w.conf(true)
	if strings.Contains(shown, w.d.Priv) || !strings.Contains(shown, "PrivateKey = "+wgHidden) {
		t.Fatal("в показанной конфигурации закрытый ключ должен быть скрыт")
	}
	// ошибки называют строку
	for _, bad := range []string{
		strings.Replace(shown, "ListenPort = 51820", "ListenPort = 99999", 1),
		strings.Replace(shown, "Address = 10.253.0.1/24", "Address = 10.253.0.7/16", 1),
		strings.Replace(shown, "AllowedIPs = 10.253.0.3/32", "AllowedIPs = 10.253.0.2/32", 1),
		shown + "\nSaveConfig = true\n",
		"мусор",
	} {
		if _, err := w.applyConf(bad); err == nil {
			t.Errorf("конфигурация должна отклоняться:\n%s", bad)
		}
	}
	// правка: новый порт, PostUp, удаление второго клиента, ключи оставлены скрытыми
	edited := strings.Replace(shown, "ListenPort = 51820", "ListenPort = 51900\nPostUp = echo up", 1)
	edited = edited[:strings.LastIndex(edited, "[Peer]")]
	if _, err := w.applyConf(edited); err != nil {
		t.Fatal(err)
	}
	if cfg("wg.port", "") != "51900" || len(w.d.Clients) != n0-1 || w.d.Extra[0] != "PostUp = echo up" {
		t.Fatalf("правка не применилась: порт %s, клиентов %d, доп. строки %v", cfg("wg.port", ""), len(w.d.Clients), w.d.Extra)
	}
	if w.d.Clients[0].Psk == wgHidden || w.d.Priv == wgHidden {
		t.Fatal("скрытые ключи должны сохраниться прежними")
	}
	disk, _ := S.ReadFile(w.confPath())
	if !strings.Contains(disk, "ListenPort = 51900") || !strings.Contains(disk, "PostUp = echo up") {
		t.Fatal("файл сервера не записан")
	}
	files := w.backupFiles()
	if len(files) == 0 {
		t.Fatal("перед правкой должна появиться резервная копия")
	}
	if _, err := w.Do("restore", map[string]string{"row": files[0]}); err != nil {
		t.Fatal(err)
	}
	if cfg("wg.port", "51820") != "51820" || len(w.d.Clients) != n0 {
		t.Errorf("восстановление: порт %s, клиентов %d", cfg("wg.port", ""), len(w.d.Clients))
	}
	if _, err := w.Do("restore", map[string]string{"row": "../config.json"}); err == nil {
		t.Error("восстановление должно принимать только имена копий")
	}
}

func TestWgServerSubnetKeyAndRecreate(t *testing.T) {
	setup(t)
	w := wgMod
	ip := w.d.Clients[0].IP
	rt.Clients[ip] = "p-test"
	if err := w.Set("wg.subnet", "10.77.5"); err != nil {
		t.Fatal(err)
	}
	nip := strings.Replace(ip, "10.253.0", "10.77.5", 1)
	if w.d.Clients[0].IP != nip || rt.Clients[nip] != "p-test" {
		t.Fatalf("клиент должен переехать в новую подсеть вместе с профилем: %s → %s, профиль %q", ip, w.d.Clients[0].IP, rt.Clients[nip])
	}
	for _, kv := range [][2]string{{"wg.port", "0"}, {"wg.mtu", "9000"}, {"wg.dns", "1.1.1"}, {"wg.allowed", "10.0.0.0"}, {"wg.endpoint", "a b"}, {"wg.subnet", "10.300.1"}} {
		if w.Set(kv[0], kv[1]) == nil {
			t.Errorf("%s = %q должно отклоняться", kv[0], kv[1])
		}
	}
	if err := w.Set("wg.dns", "9.9.9.9, 1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if err := w.Set("wg.endpoint", "vpn.example.org:443"); err != nil {
		t.Fatal(err)
	}
	cc := w.clientConf(w.d.Clients[0])
	if !strings.Contains(cc, "DNS = 9.9.9.9, 1.1.1.1") || !strings.Contains(cc, "Endpoint = vpn.example.org:443") {
		t.Errorf("настройки для клиентов должны попадать в их конфигурацию:\n%s", cc)
	}
	if _, err := w.Do("config", map[string]string{"row": nip}); err != nil {
		t.Fatal(err)
	}
	if tb := w.Tables(); !tb[0].Top || tb[0].Img == "" || tb[0].File == "" {
		t.Errorf("конфигурация клиента должна показываться с QR и кнопкой скачивания: %+v", tb[0])
	}
	pub := w.d.Pub
	if _, err := w.Do("regen", nil); err != nil || w.d.Pub == pub {
		t.Errorf("смена ключа сервера: %v", err)
	}
	if _, err := w.Do("recreate", map[string]string{"word": "да"}); err == nil {
		t.Error("создание заново без слова ЗАНОВО должно отклоняться")
	}
	if _, err := w.Do("recreate", map[string]string{"word": "заново"}); err != nil || len(w.d.Clients) != 0 {
		t.Errorf("создание заново: %v, клиентов %d", err, len(w.d.Clients))
	}
}

func TestInternetHasNoTab(t *testing.T) {
	setup(t)
	if hasPage(mod("inet")) {
		t.Error("у модуля «Интернет» не должно быть своей вкладки")
	}
	if !hasPage(mod("meduza")) || !hasPage(wgMod) || !fieldsFirst(wgMod) {
		t.Error("у MeduzaVPN и WG-Server вкладки есть, у WG-Server настройки наверху")
	}
	if len(mod("inet").Checks()) == 0 {
		t.Error("системные проверки «Интернета» должны остаться в диагностике")
	}
}

func TestQRMatchesWindowsEncoder(t *testing.T) {
	// эталон — Qr.cs Windows-версии: текст «A», уровень M, маска 0 (21×21)
	g, err := qrEncode("A", 1, 0)
	if err != nil || g.n != 21 {
		t.Fatal(err)
	}
	row := func(y int) string {
		var b strings.Builder
		for x := 0; x < g.n; x++ {
			if g.m[y][x] {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
		return b.String()
	}
	if row(0) != "111111100111001111111" || row(9) != "100111000100001000110" {
		t.Errorf("QR расходится с Qr.cs: строка 0 %s, строка 9 %s", row(0), row(9))
	}
	if _, err := qrEncode(strings.Repeat("x", 3000), 1, -1); err == nil {
		t.Error("слишком длинный текст должен давать ошибку")
	}
	if qrImage(strings.Repeat("x", 2400)) == "" {
		t.Error("длинная конфигурация должна помещаться хотя бы с уровнем L")
	}
}
