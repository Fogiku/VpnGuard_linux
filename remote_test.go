package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// recorder — минимальный http.ResponseWriter для тестов (net/http/httptest на этом ПК недоступен).
type recorder struct {
	h    http.Header
	Code int
	body strings.Builder
}

func (r *recorder) Header() http.Header {
	if r.h == nil {
		r.h = http.Header{}
	}
	return r.h
}
func (r *recorder) Write(b []byte) (int, error) {
	if r.Code == 0 {
		r.Code = 200
	}
	return r.body.Write(b)
}
func (r *recorder) WriteHeader(c int) { r.Code = c }

func remoteGet(path, token, from string) (int, string) {
	r, _ := http.NewRequest(http.MethodGet, "http://gw:8765"+path, nil)
	r.RemoteAddr = from + ":50000"
	if token != "" {
		r.Header.Set("X-Token", token)
	}
	w := &recorder{}
	remoteServe(w, r)
	return w.Code, w.body.String()
}

func TestRemoteDiagnostics(t *testing.T) {
	setup(t)
	webToken()
	if c, _ := remoteGet("/status", "x", "192.168.1.10"); c != http.StatusForbidden {
		t.Fatalf("выключенная диагностика должна отказывать, код %d", c)
	}
	if _, err := remMod.Do("enable", nil); err != nil {
		t.Fatal(err)
	}
	tok := cfg("remote.token", "")
	if len(tok) < 16 || !remoteOn() {
		t.Fatal("после включения нужен токен и срок")
	}
	if c, _ := remoteGet("/status", "неверный", "192.168.1.10"); c != http.StatusUnauthorized {
		t.Errorf("неверный токен: код %d", c)
	}
	if c, _ := remoteGet("/status", tok, "8.8.8.8"); c != http.StatusForbidden {
		t.Errorf("по умолчанию — только домашняя сеть, из интернета код %d", c)
	}
	c, idx := remoteGet("/", tok, "192.168.1.10")
	if c != 200 || !strings.Contains(idx, "/bundle") {
		t.Fatalf("список отчётов: %d %q", c, idx)
	}
	// в отчётах нет ключей и паролей
	wgMod.viewIP = wgMod.d.Clients[0].IP // на странице открыт QR клиента с его закрытым ключом
	c, all := remoteGet("/bundle", tok, "192.168.1.10")
	_, st := remoteGet("/status", tok, "10.253.0.5")
	all += st
	if c != 200 {
		t.Fatalf("/bundle: код %d", c)
	}
	for name, secret := range map[string]string{"ключ сервера": wgMod.d.Priv, "ключ клиента": wgMod.d.Clients[0].Priv, "общий ключ": wgMod.d.Clients[0].Psk,
		"пароль веба": cfg("web.token", ""), "токен диагностики": tok} {
		if secret != "" && strings.Contains(all, secret) {
			t.Errorf("в отчёт попал секрет: %s", name)
		}
	}
	if strings.Contains(all, "data:image") {
		t.Error("QR-коды (в них ключи клиентов) должны быть скрыты")
	}
	for _, part := range []string{"Проверки", "Журнал решений", "Сеть", "Система", "Файлы", "Журнал агента", "клиенты WG-Server"} {
		if !strings.Contains(all, part) {
			t.Errorf("в /bundle нет раздела %q", part)
		}
	}
	// команды: по умолчанию запрещены; разрешённые — только безопасные
	if c, _ := remoteGet("/cmd?c=meduza.reconnect", tok, "192.168.1.10"); c != http.StatusBadRequest {
		t.Errorf("команды без разрешения: код %d", c)
	}
	setCfg("remote.allowActions", "true")
	if c, b := remoteGet("/cmd?c=meduza.reconnect", tok, "192.168.1.10"); c != 200 {
		t.Errorf("meduza.reconnect: %d %s", c, b)
	}
	for _, bad := range []string{"meduza.logout", "wg.regen", "wg.recreate", "wg.add", "remote.disable", "meduza.loginpw"} {
		if c, _ := remoteGet("/cmd?c="+bad, tok, "192.168.1.10"); c != http.StatusBadRequest {
			t.Errorf("опасная команда %s должна отклоняться, код %d", bad, c)
		}
	}
	if c, b := remoteGet("/cmd?c=fix:wg.enabled", tok, "192.168.1.10"); c != 200 {
		t.Errorf("исправление проверки: %d %s", c, b)
	}
	// откуда угодно — по выбору; новый токен отменяет старый; срок истёк — выключается сама
	setCfg("remote.allowFrom", "any")
	if c, _ := remoteGet("/status", tok, "8.8.8.8"); c != 200 {
		t.Errorf("«откуда угодно»: код %d", c)
	}
	_, _ = remMod.Do("newtoken", nil)
	if c, _ := remoteGet("/status", tok, "192.168.1.10"); c != http.StatusUnauthorized {
		t.Errorf("старый токен после смены: код %d", c)
	}
	setCfg("remote.until", time.Now().Add(-time.Minute).Format(time.RFC3339))
	remMod.Tick()
	if remoteOn() || cfgBool("remote.enabled", true) {
		t.Error("по истечении срока диагностика должна выключиться")
	}
	if !strings.Contains(remMod.Status().State, "Выключена") {
		t.Errorf("состояние: %q", remMod.Status().State)
	}
	if hideSecrets("PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=") != "PrivateKey = (скрыт)" {
		t.Error("hideSecrets: ключ WireGuard")
	}
}
