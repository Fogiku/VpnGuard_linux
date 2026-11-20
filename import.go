// Перенос настроек из Windows-версии VpnGuard: vpnguard --import ПАПКА.
// Содержимое папки экспорта:
//
//	wg_server.conf   — конфигурация сервера WireGuard (data\wg\wg_server.conf);
//	clients\*.conf   — конфигурации клиентов (data\clients и C:\ProgramData\VpnGuard\clients): из них берутся
//	                   закрытые ключи клиентов (для QR) и адрес сервера для клиентов;
//	config.json      — настройки Windows-версии (раздел "wg": endpoint, clientDns, clientAllowedIPs, clientKeepalive).
//
// Ключ сервера и ключи клиентов сохраняются как были — клиентам ничего перенастраивать не нужно.
package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// pubOf — открытый ключ WireGuard по закрытому (X25519), без вызова wg.
func pubOf(priv string) string {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(priv))
	if err != nil || len(b) != 32 {
		return ""
	}
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

// normWindowsConf — привести файл сервера Windows к формату, который принимает parseServerConf:
// имя клиента из «# Name = …» — первой строкой блока, прочие комментарии убираются, адрес без маски — /32,
// PersistentKeepalive = 0 (выключен) не переносится, неизвестные параметры пропускаются с предупреждением.
func normWindowsConf(text string) (string, []string) {
	var out, warn []string
	sec := ""
	var peer []string
	name := ""
	flush := func() {
		if sec == "Peer" {
			out = append(out, "[Peer]")
			if name != "" {
				out = append(out, "# "+name)
			}
			out = append(out, peer...)
		}
		peer, name = nil, ""
	}
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		l := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
		switch {
		case l == "":
			continue
		case strings.EqualFold(l, "[Interface]"):
			flush()
			sec = "Interface"
			out = append(out, "[Interface]")
			continue
		case strings.EqualFold(l, "[Peer]"):
			flush()
			sec = "Peer"
			continue
		case strings.HasPrefix(l, "#"):
			c := strings.TrimSpace(strings.TrimPrefix(l, "#"))
			if k, v, ok := strings.Cut(c, "="); ok && sec == "Peer" && strings.EqualFold(strings.TrimSpace(k), "name") {
				name = strings.TrimSpace(v)
			}
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			warn = append(warn, "пропущена строка: "+l)
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch sec + "." + strings.ToLower(k) {
		case "Interface.privatekey", "Interface.address", "Interface.listenport", "Interface.mtu":
			out = append(out, k+" = "+v)
		case "Peer.publickey", "Peer.presharedkey":
			peer = append(peer, k+" = "+v)
		case "Peer.allowedips":
			// у сервера на клиента — один адрес; лишние сети (подсети за роутером) — предупреждение
			parts := strings.Split(v, ",")
			ip := strings.TrimSpace(parts[0])
			if !strings.Contains(ip, "/") {
				ip += "/32"
			}
			if len(parts) > 1 {
				warn = append(warn, fmt.Sprintf("клиент %q: перенесён только адрес %s, сети %s не перенесены", name, ip, strings.Join(parts[1:], ",")))
			}
			peer = append(peer, "AllowedIPs = "+ip)
		case "Peer.persistentkeepalive":
			if v != "0" && v != "" {
				peer = append(peer, k+" = "+v)
			}
		case "Peer.endpoint":
			peer = append(peer, k+" = "+v)
		default:
			warn = append(warn, fmt.Sprintf("параметр %s в [%s] не перенесён (на Linux не нужен)", k, sec))
		}
	}
	flush()
	return strings.Join(out, "\n") + "\n", warn
}

// clientConf — то, что нужно из конфигурации клиента.
type clientConf struct{ priv, dns, endpoint, allowed, keepalive string }

func readClientConf(text string) clientConf {
	var c clientConf
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(raw), "=")
		if !ok || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "privatekey":
			c.priv = v
		case "dns":
			c.dns = v
		case "endpoint":
			c.endpoint = v
		case "allowedips":
			c.allowed = v
		case "persistentkeepalive":
			c.keepalive = v
		}
	}
	return c
}

// importWindows — перенести WG-Server из папки dir. Возвращает отчёт для журнала установки.
func importWindows(dir string) (string, error) {
	text, err := os.ReadFile(filepath.Join(dir, "wg_server.conf"))
	if err != nil {
		return "", fmt.Errorf("нет файла wg_server.conf в %s", dir)
	}
	norm, warn := normWindowsConf(string(text))
	for _, w := range warn {
		if strings.Contains(w, "не перенесены") {
			return "", errors.New("нельзя перенести клиента без потери маршрутов: " + w)
		}
	}
	priv, sub, port, mtu, extra, peers, err := wgMod.parseServerConf(norm)
	if err != nil {
		return "", fmt.Errorf("wg_server.conf: %w", err)
	}
	if priv == wgHidden {
		return "", errors.New("в wg_server.conf скрыт закрытый ключ — нужен сам файл, а не копия из отчёта")
	}
	pub := pubOf(priv)
	if pub == "" {
		return "", errors.New("wg_server.conf: неверный PrivateKey")
	}
	// клиентские конфигурации: закрытые ключи по совпадению открытого ключа
	byPub := map[string]clientConf{}
	var common []clientConf
	files, _ := filepath.Glob(filepath.Join(dir, "clients", "*.conf"))
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		c := readClientConf(string(b))
		if p := pubOf(c.priv); p != "" {
			byPub[p] = c
			common = append(common, c)
		}
	}
	d := wgData{Priv: priv, Pub: pub, Extra: extra}
	withKey := 0
	for i, p := range peers {
		name := p.name
		if name == "" {
			name = fmt.Sprintf("клиент %d", i+1)
		}
		c := &WgClient{Name: name, IP: p.ip, Pub: p.pub, Psk: p.psk, Extra: p.extra}
		if cc, ok := byPub[p.pub]; ok {
			c.Priv = cc.priv
			withKey++
		}
		d.Clients = append(d.Clients, c)
	}
	// настройки для клиентов: Windows config.json, затем первая клиентская конфигурация
	var win struct {
		Wg struct {
			Endpoint, ClientDns, ClientAllowedIPs string
			ClientKeepalive                       json.Number
			ClientOff                             []string
		} `json:"wg"`
	}
	if b, err := os.ReadFile(filepath.Join(dir, "config.json")); err == nil {
		if err := json.Unmarshal([]byte(strings.TrimPrefix(string(b), "\ufeff")), &win); err != nil {
			return "", fmt.Errorf("config.json: %w", err)
		}
	}
	endpoint, dns, allowed, ka := win.Wg.Endpoint, win.Wg.ClientDns, win.Wg.ClientAllowedIPs, win.Wg.ClientKeepalive.String()
	if len(common) > 0 {
		c := common[0]
		if endpoint == "" {
			endpoint = c.endpoint
		}
		if dns == "" {
			dns = c.dns
		}
		if allowed == "" {
			allowed = c.allowed
		}
		if ka == "" {
			ka = c.keepalive
		}
	}
	for _, ip := range win.Wg.ClientOff {
		for _, c := range d.Clients {
			if c.IP == strings.TrimSpace(strings.Split(ip, "/")[0]) {
				c.Off = true
			}
		}
	}
	// «внешний адрес:порт» — порт отдельно не храним, если совпадает с портом сервера
	if h, p, err := net.SplitHostPort(endpoint); err == nil && p == port {
		endpoint = h
	}
	if err := saveJSON("wg.json", d); err != nil {
		return "", fmt.Errorf("сохранение wg.json: %w", err)
	}
	wgMod.d = d
	if err := setCfg("wg.subnet", sub); err != nil {
		return "", err
	}
	if err := setCfg("wg.port", port); err != nil {
		return "", err
	}
	if mtu != "" {
		if err := setCfg("wg.mtu", mtu); err != nil {
			return "", err
		}
	}
	for k, v := range map[string]string{"wg.endpoint": endpoint, "wg.dns": dns, "wg.allowed": strings.ReplaceAll(allowed, " ", ""), "wg.keepalive": ka} {
		if v != "" {
			if err := setCfg(k, v); err != nil {
				return "", err
			}
		}
	}
	var r strings.Builder
	fmt.Fprintf(&r, "WG-Server перенесён: сервер %s.1/24, UDP %s, открытый ключ %s\n", sub, port, pub)
	fmt.Fprintf(&r, "Клиентов: %d, из них с конфигурацией (QR на странице): %d\n", len(d.Clients), withKey)
	for _, c := range d.Clients {
		k := "без конфигурации у шлюза — устройство подключается своей, как раньше"
		if c.Priv != "" {
			k = "конфигурация есть"
		}
		fmt.Fprintf(&r, "  %-24s %-15s %s\n", c.Name, c.IP, k)
	}
	fmt.Fprintf(&r, "Внешний адрес для клиентов: %s\n", orDash(endpoint))
	for _, w := range warn {
		r.WriteString("Внимание: " + w + "\n")
	}
	Decide("INFO", "Импорт из Windows-версии: WG-Server %s.1/24, клиентов %d", sub, len(d.Clients))
	return r.String(), nil
}
