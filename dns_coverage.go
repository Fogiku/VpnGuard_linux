package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// nft JSON represents interval-set members as an address, a closed range or a prefix.
func addressMember(raw json.RawMessage, ip netip.Addr) (bool, error) {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		addr, err := netip.ParseAddr(single)
		if err == nil && addr.Is4() {
			return ip == addr, nil
		}
	}
	var elem struct {
		Range  []string `json:"range"`
		Prefix *struct {
			Addr string `json:"addr"`
			Len  *int   `json:"len"`
		} `json:"prefix"`
	}
	if json.Unmarshal(raw, &elem) == nil {
		if len(elem.Range) == 2 && elem.Prefix == nil {
			a, e1 := netip.ParseAddr(elem.Range[0])
			b, e2 := netip.ParseAddr(elem.Range[1])
			if e1 == nil && e2 == nil && a.Is4() && b.Is4() && a.Compare(b) <= 0 {
				return a.Compare(ip) <= 0 && ip.Compare(b) <= 0, nil
			}
		}
		if elem.Prefix != nil && elem.Prefix.Len != nil && elem.Range == nil {
			a, err := netip.ParseAddr(elem.Prefix.Addr)
			p := netip.PrefixFrom(a, *elem.Prefix.Len)
			if err == nil && a.Is4() && p.IsValid() {
				return p.Contains(ip), nil
			}
		}
	}
	return false, fmt.Errorf("неизвестный элемент набора nft")
}

func ruleSetContains(output, name string, ip netip.Addr) (bool, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Family, Table, Name, Type string
				Elem                      []json.RawMessage
			}
		}
	}
	if len(output) > 4<<20 || json.Unmarshal([]byte(output), &doc) != nil {
		return false, fmt.Errorf("не удалось разобрать набор nft")
	}
	for _, obj := range doc.Nftables {
		set := obj.Set
		if set == nil || set.Family != "inet" || set.Table != "vpnguard" || set.Name != name || set.Type != "ipv4_addr" {
			continue
		}
		for _, elem := range set.Elem {
			found, err := addressMember(elem, ip)
			if err != nil || found {
				return found, err
			}
		}
		return false, nil
	}
	return false, fmt.Errorf("набор правила отсутствует в ответе nft")
}

func dnsCacheCoverage(name, ip string) string {
	if routingDNS == nil || !cfgBool("dns.enabled", true) {
		return "DNS-кэш выключен"
	}
	routingDNS.mu.Lock()
	defer routingDNS.mu.Unlock()
	entry, ok := routingDNS.entries[name]
	if !ok {
		return "нет записи для этого имени"
	}
	now := routingDNS.now()
	if ttl := entry.Addresses[ip].Sub(now); ttl > 0 {
		return fmt.Sprintf("адрес есть, остаток TTL %d с", int(ttl.Seconds()))
	}
	return "адреса нет среди действующих A-записей этого имени"
}

func compareDNSAddress(args map[string]string) (string, error) {
	name := dnsName(strings.TrimSpace(args["name"]))
	ip, err := netip.ParseAddr(strings.TrimSpace(args["ip"]))
	if !reDomain.MatchString(name) || err != nil || !ip.Is4() {
		return "", fmt.Errorf("укажите доменное имя и IPv4, полученный клиентом")
	}
	tag := args["rule"]
	title, ok := ruleLabels()[tag]
	if !ok {
		return "", fmt.Errorf("выберите существующее правило")
	}
	peer := ""
	if client := strings.TrimSpace(args["client"]); client != "" {
		addr, err := netip.ParseAddr(client)
		if err != nil || !addr.Is4() {
			return "", fmt.Errorf("нужен IPv4 источника DNS-запроса")
		}
		detail := "наблюдение недоступно"
		if routingDNS != nil {
			detail = routingDNS.peerCoverage(addr.String(), name, ip.String())
		}
		peer = "\nОтвет DNS-клиенту: " + detail + "."
	}
	set := routeAddressSet(tag)
	cache := dnsCacheCoverage(name, ip.String())
	kernel := "набор недоступен"
	if Sim {
		kernel = "реальное ядро в симуляторе не опрашивается"
	} else if output, code := S.Run(3*time.Second, "", "nft", "-j", "list", "set", "inet", "vpnguard", set); code == 0 {
		found, err := ruleSetContains(output, set, ip)
		switch {
		case err != nil:
			kernel = err.Error()
		case found:
			kernel = "адрес входит в действующий набор"
		default:
			kernel = "адрес отсутствует в действующем наборе"
		}
	}
	return fmt.Sprintf("%s · %s\nTTL-кэш шлюза: %s.%s\nПравило «%s»: %s.\nПроверено %s UTC. Совпадение адреса — одно из условий правила; выход конкретного соединения проверяется отдельно.", name, ip, cache, peer, title, kernel, time.Now().UTC().Format("15:04:05")), nil
}
