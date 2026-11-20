package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(t *testing.T) (priv, pub string) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

// Файлы в том виде, как их ведёт Windows-версия на 192.168.1.66 (формат взят из отчёта диагностики).
func TestImportFromWindows(t *testing.T) {
	setup(t)
	sp, spub := testKey(t)
	if pubOf(sp) != spub {
		t.Fatal("pubOf не совпадает с X25519")
	}
	_, mik := testKey(t)
	_, kee := testKey(t)
	pocoPriv, poco := testKey(t)
	foldPriv, fold := testKey(t)
	_, psk := testKey(t)
	dir := t.TempDir()
	conf := "\ufeff# wg\r\n[Interface]\r\nListenPort=51820\r\nAddress=192.168.15.1/24\r\nPrivateKey=" + sp + "\r\n\r\n\r\n" +
		"[Peer]\n# Name = Mikrotik RB5009UG\nPublicKey=" + mik + "\nAllowedIPs=192.168.15.5/32\nPersistentKeepalive=0\n\n" +
		"[Peer]\n# Name = Keenetic Giga\nPublicKey=" + kee + "\nAllowedIPs=192.168.15.2\nPersistentKeepalive=0\n\n" +
		"[Peer]\n# Name = POCO X3\n# VpnGuard: created 2026-11-03 11:53\nPublicKey = " + poco + "\nPresharedKey = " + psk + "\nAllowedIPs = 192.168.15.10/32\n\n" +
		"[Peer]\n# Name = Samsung Fold 8\n# VpnGuard: created 2026-11-04 17:30\nPublicKey = " + fold + "\nPresharedKey = " + psk + "\nAllowedIPs = 192.168.15.11/32\n"
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "wg_server.conf"), []byte(conf), 0o600))
	must(os.MkdirAll(filepath.Join(dir, "clients"), 0o700))
	cl := func(priv, ip string) string {
		return "[Interface]\nPrivateKey = " + priv + "\nAddress = " + ip + "/32\nDNS = 8.8.8.8, 1.1.1.1\n\n[Peer]\nPublicKey = " + spub +
			"\nPresharedKey = " + psk + "\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = home.example.net:51820\nPersistentKeepalive = 25\n"
	}
	must(os.WriteFile(filepath.Join(dir, "clients", "POCO_X3.conf"), []byte(cl(pocoPriv, "192.168.15.10")), 0o600))
	must(os.WriteFile(filepath.Join(dir, "clients", "Samsung_Fold_8.conf"), []byte(cl(foldPriv, "192.168.15.11")), 0o600))
	must(os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"wg":{"endpoint":"","clientDns":"","clientOff":[]}}`), 0o600))

	r, err := importWindows(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(r)
	d := wgMod.d
	if d.Priv != sp || d.Pub != spub || len(d.Clients) != 4 {
		t.Fatalf("сервер: ключ %v, клиентов %d", d.Priv == sp, len(d.Clients))
	}
	want := map[string]string{"Mikrotik RB5009UG": "192.168.15.5", "Keenetic Giga": "192.168.15.2", "POCO X3": "192.168.15.10", "Samsung Fold 8": "192.168.15.11"}
	for _, c := range d.Clients {
		if want[c.Name] != c.IP {
			t.Errorf("клиент %q: адрес %s", c.Name, c.IP)
		}
		if (c.Name == "POCO X3") != (c.Priv == pocoPriv) && c.Name != "Samsung Fold 8" {
			t.Errorf("клиент %q: ключ из конфигурации клиента", c.Name)
		}
		if strings.Contains(c.Extra, "Keepalive = 0") {
			t.Errorf("клиент %q: PersistentKeepalive=0 не переносится", c.Name)
		}
	}
	if cfg("wg.subnet", "") != "192.168.15" || cfg("wg.port", "") != "51820" || cfg("wg.endpoint", "") != "home.example.net" ||
		cfg("wg.dns", "") != "8.8.8.8, 1.1.1.1" || cfg("wg.allowed", "") != "0.0.0.0/0,::/0" || cfg("wg.keepalive", "") != "25" {
		t.Errorf("настройки: %s %s %s %q %s %s", cfg("wg.subnet", ""), cfg("wg.port", ""), cfg("wg.endpoint", ""), cfg("wg.dns", ""), cfg("wg.allowed", ""), cfg("wg.keepalive", ""))
	}
	// файл сервера, который запишет агент, принимается его же проверкой и содержит прежние ключи
	text := wgMod.conf(false)
	if _, _, _, _, _, peers, err := wgMod.parseServerConf(text); err != nil || len(peers) != 4 {
		t.Fatalf("итоговый файл: %v (%d клиентов)\n%s", err, len(peers), text)
	}
	if !strings.Contains(text, "PrivateKey = "+sp) || !strings.Contains(text, "# Keenetic Giga") {
		t.Error("в итоговом файле нет ключа сервера или имени клиента")
	}
	// QR клиента, у которого есть конфигурация, строится; ключи не меняются
	if _, err := importWindows(t.TempDir()); err == nil {
		t.Error("пустая папка должна давать ошибку")
	}
}
