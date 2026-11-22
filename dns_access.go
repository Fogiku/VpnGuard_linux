package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync/atomic"
)

type dnsAllowFunc func(net.IP) bool
type dnsAccessPolicy struct{ value atomic.Value }

func newDNSAccessPolicy(allow dnsAllowFunc) *dnsAccessPolicy {
	p := &dnsAccessPolicy{}
	p.set(allow)
	return p
}
func (p *dnsAccessPolicy) set(allow dnsAllowFunc) { p.value.Store(allow) }
func (p *dnsAccessPolicy) allows(ip net.IP) bool {
	fn, _ := p.value.Load().(dnsAllowFunc)
	return fn != nil && ip != nil && ip.To4() != nil && fn(ip.To4())
}

type dnsClientSettings struct {
	Enabled                bool
	Upstream               string
	WG                     bool
	WGAddress, WGInterface string
	LANAddress             string
	LANNetworks            []*net.IPNet
	LANText                string
}
type dnsClientPlan struct {
	Kind      string `json:"kind"`
	Address   string `json:"address"`
	Interface string `json:"interface"`
	Sources   string `json:"sources"`
	allow     dnsAllowFunc
}

func (p dnsClientPlan) key() string { return p.Address + "@" + p.Interface }

type dnsClientListener struct {
	plan   dnsClientPlan
	policy *dnsAccessPolicy
	stop   func()
}

func privateIPv4(ip net.IP) bool {
	v := ip.To4()
	return v != nil && (v[0] == 10 || v[0] == 172 && v[1] >= 16 && v[1] <= 31 || v[0] == 192 && v[1] == 168)
}
func parseDNSLANNetworks(value string) ([]*net.IPNet, string, error) {
	var networks []*net.IPNet
	seen := map[string]bool{}
	var canonical []string
	for _, token := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' || r == '\t' }) {
		ip, n, err := net.ParseCIDR(token)
		if err != nil || ip.To4() == nil {
			return nil, "", fmt.Errorf("DNS LAN: нужна частная IPv4-подсеть")
		}
		ones, bits := n.Mask.Size()
		last := append(net.IP(nil), n.IP.To4()...)
		for i := range last {
			last[i] |= ^n.Mask[i]
		}
		if bits != 32 || ones == 0 || !privateIPv4(n.IP) || !privateIPv4(last) {
			return nil, "", fmt.Errorf("DNS LAN: разрешены только подсети 10/8, 172.16/12 и 192.168/16")
		}
		name := n.String()
		if !seen[name] {
			seen[name] = true
			canonical = append(canonical, name)
			networks = append(networks, n)
		}
	}
	if len(networks) > 16 {
		return nil, "", fmt.Errorf("DNS LAN: максимум 16 подсетей")
	}
	sort.Strings(canonical)
	return networks, strings.Join(canonical, ", "), nil
}

func readDNSClientSettings(overrides map[string]string) (dnsClientSettings, error) {
	cfgMu.Lock()
	values := make(map[string]string, len(cfgMap))
	for k, v := range cfgMap {
		values[k] = v
	}
	cfgMu.Unlock()
	for k, v := range overrides {
		values[k] = v
	}
	get := func(k, def string) string {
		if v, ok := values[k]; ok {
			return v
		}
		return def
	}
	for _, key := range []string{"dns.enabled", "dns.serveWG"} {
		v := get(key, map[string]string{"dns.enabled": "true", "dns.serveWG": "false"}[key])
		if v != "true" && v != "false" {
			return dnsClientSettings{}, fmt.Errorf("%s: нужно true или false", key)
		}
	}
	s := dnsClientSettings{Enabled: get("dns.enabled", "true") == "true", Upstream: get("dns.upstream", "127.0.0.53:53"), WG: get("dns.serveWG", "false") == "true", WGInterface: get("wg.iface", "wg_server"), LANAddress: strings.TrimSpace(get("dns.lanAddress", ""))}
	s.WGAddress = get("wg.subnet", "10.253.0") + ".1"
	if !validDNSUpstream(s.Upstream) {
		return s, fmt.Errorf("DNS: неверный upstream или петля к локальному прокси")
	}
	var err error
	s.LANNetworks, s.LANText, err = parseDNSLANNetworks(get("dns.allowLAN", ""))
	if err != nil {
		return s, err
	}
	if s.WG {
		if ip := net.ParseIP(s.WGAddress); ip == nil || ip.To4() == nil || !privateIPv4(ip) || len(s.WGInterface) == 0 || len(s.WGInterface) > 15 || strings.ContainsRune(s.WGInterface, 0) {
			return s, fmt.Errorf("DNS WG: неверные IPv4-адрес или интерфейс сервера")
		}
	}
	if s.LANAddress != "" {
		ip := net.ParseIP(s.LANAddress)
		if ip == nil || ip.To4() == nil || !privateIPv4(ip) || s.LANAddress == s.WGAddress {
			return s, fmt.Errorf("DNS LAN: нужен отдельный частный IPv4-адрес этого ПК")
		}
		s.LANAddress = ip.To4().String()
		if len(s.LANNetworks) == 0 {
			return s, fmt.Errorf("DNS LAN: сначала укажите разрешённые подсети")
		}
	}
	host, port, _ := net.SplitHostPort(s.Upstream)
	if port == "53" && (host == s.WGAddress || s.LANAddress != "" && host == s.LANAddress) {
		return s, fmt.Errorf("DNS upstream не может указывать на клиентский DNS этого шлюза")
	}
	return s, nil
}

func interfaceForDNSIP(ip string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			value, _, err := net.ParseCIDR(address.String())
			if err == nil && value.Equal(net.ParseIP(ip)) {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("DNS: адрес %s не назначен активному интерфейсу", ip)
}

func (s dnsClientSettings) plans(sim bool) ([]dnsClientPlan, error) {
	if !s.Enabled {
		return nil, nil
	}
	var plans []dnsClientPlan
	if s.WG {
		if !sim {
			iface, err := interfaceForDNSIP(s.WGAddress)
			if err != nil {
				return nil, err
			}
			if iface != s.WGInterface {
				return nil, fmt.Errorf("DNS WG: адрес %s принадлежит %s, ожидается %s", s.WGAddress, iface, s.WGInterface)
			}
		}
		ip := net.ParseIP(s.WGAddress).To4()
		network := &net.IPNet{IP: ip.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}
		plans = append(plans, dnsClientPlan{Kind: "WG", Address: net.JoinHostPort(s.WGAddress, "53"), Interface: s.WGInterface, Sources: network.String() + " через WireGuard", allow: func(peer net.IP) bool { return network.Contains(peer) }})
	}
	if s.LANAddress != "" {
		iface := "имитация"
		var err error
		if !sim {
			iface, err = interfaceForDNSIP(s.LANAddress)
			if err != nil {
				return nil, err
			}
			if iface == s.WGInterface {
				return nil, fmt.Errorf("DNS LAN: выберите LAN-интерфейс, а не WireGuard")
			}
		}
		networks := s.LANNetworks
		plans = append(plans, dnsClientPlan{Kind: "LAN", Address: net.JoinHostPort(s.LANAddress, "53"), Interface: iface, Sources: s.LANText, allow: func(peer net.IP) bool {
			for _, n := range networks {
				if n.Contains(peer) {
					return true
				}
			}
			return false
		}})
	}
	return plans, nil
}

// Новые сокеты до записи настроек принимают только REFUSED. Прежние остаются
// открытыми, если любой новый адрес/порт занять не удалось.
func (m *dnsModule) prepareClients(plans []dnsClientPlan) (map[string]*dnsClientListener, error) {
	staged := map[string]*dnsClientListener{}
	for _, plan := range plans {
		key := plan.key()
		if old := m.clients[key]; old != nil {
			staged[key] = old
			continue
		}
		policy := newDNSAccessPolicy(func(net.IP) bool { return false })
		stop, err := startDNSListenerWithAccess(plan.Address, plan.Interface, plan.Kind, policy, routingDNS, dnsApplyAnswer)
		if err != nil {
			m.discardClients(staged)
			return nil, fmt.Errorf("DNS %s (%s): %w", plan.Kind, plan.Address, err)
		}
		staged[key] = &dnsClientListener{plan: plan, policy: policy, stop: stop}
	}
	return staged, nil
}
func (m *dnsModule) discardClients(staged map[string]*dnsClientListener) {
	for key, listener := range staged {
		if m.clients[key] != listener {
			listener.stop()
		}
	}
}
func (m *dnsModule) publishClients(staged map[string]*dnsClientListener, plans []dnsClientPlan) {
	for _, plan := range plans {
		listener := staged[plan.key()]
		listener.plan = plan
		listener.policy.set(plan.allow)
	}
	old := m.clients
	m.clients = staged
	for key, listener := range old {
		if staged[key] != listener {
			listener.stop()
		}
	}
}
func (m *dnsModule) clientStatus() map[string]any {
	m.tk.Lock()
	defer m.tk.Unlock()
	settings, err := readDNSClientSettings(nil)
	listeners := []dnsClientPlan{}
	for _, listener := range m.clients {
		listeners = append(listeners, listener.plan)
	}
	sort.Slice(listeners, func(i, j int) bool { return listeners[i].Address < listeners[j].Address })
	desired, planErr := settings.plans(Sim)
	if Sim {
		listeners = desired
	}
	message := m.clientError
	if err != nil {
		message = err.Error()
	}
	if planErr != nil {
		message = planErr.Error()
	}
	ready := message == "" && len(listeners) == len(desired)
	if !Sim {
		for _, plan := range desired {
			if m.clients[plan.key()] == nil {
				ready = false
			}
		}
	}
	return map[string]any{"enabled": settings.Enabled, "ready": ready, "error": message, "listeners": listeners, "simulated": Sim, "wgProfileDNS": cfg("wg.dns", "1.1.1.1"), "ipv6": "AAAA REFUSED; listeners IPv4 only"}
}

func validateWGExportDNS(value string) error {
	if value == "" {
		return nil
	}
	for _, token := range strings.Split(value, ",") {
		if net.ParseIP(strings.TrimSpace(token)) == nil {
			return fmt.Errorf("wg.dns: нужен список IP-адресов")
		}
	}
	return nil
}
