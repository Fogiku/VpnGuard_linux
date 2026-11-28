package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
	"vpnguard/internal/dnsmessage"
)

type dnsModule struct {
	base
	stop        func()
	address     string
	clients     map[string]*dnsClientListener
	clientError string
}

var dnsMod = &dnsModule{}

func init()                                { Register(dnsMod) }
func (m *dnsModule) ID() string            { return "dns" }
func (m *dnsModule) Name() string          { return "DNS" }
func (m *dnsModule) Color() string         { return "#49b8e8" }
func (m *dnsModule) Order() int            { return 15 }
func (m *dnsModule) Period() time.Duration { return 10 * time.Second }
func dnsAddress() string {
	port := cfg("dns.loopbackPort", "")
	if port != "5353" && port != "15353" {
		port = "5353"
		if Sim {
			port = "15353"
		}
	}
	return "127.0.0.1:" + port
}

func initDNS() {
	routingDNS = newDNSEngine(exchangeDNS)
	go func() {
		for {
			time.Sleep(5 * time.Second)
			if cfgBool("dns.enabled", true) && !routesStarting.Load() {
				routingDNS.refresh()
			}
		}
	}()
}
func (m *dnsModule) Tick() {
	m.tk.Lock()
	defer m.tk.Unlock()
	m.tickLocked()
}
func dnsApplyAnswer() error {
	if routesStarting.Load() {
		return fmt.Errorf("маршруты ещё запускаются")
	}
	return Apply("DNS: обновление адресов по ответу")
}
func (m *dnsModule) tickLocked() {
	if routingDNS == nil {
		m.setSt(-1, false, "Не запущен", "")
		return
	}
	if !cfgBool("dns.enabled", true) {
		if m.stop != nil {
			m.stop()
			m.stop = nil
		}
		m.publishClients(map[string]*dnsClientListener{}, nil)
		m.clientError = ""
		m.setSt(-1, false, "Выключен", "")
		return
	}
	if m.stop == nil {
		stop, err := startDNSListener(dnsAddress(), routingDNS, dnsApplyAnswer)
		if err != nil {
			m.setSt(1, false, "Не удалось открыть DNS", err.Error())
			return
		}
		m.stop, m.address = stop, dnsAddress()
	}
	settings, clientErr := readDNSClientSettings(nil)
	if clientErr == nil {
		var plans []dnsClientPlan
		plans, clientErr = settings.plans(Sim)
		if clientErr == nil {
			if Sim {
				plans = nil
			}
			var staged map[string]*dnsClientListener
			staged, clientErr = m.prepareClients(plans)
			if clientErr == nil {
				m.publishClients(staged, plans)
			}
		}
	}
	m.clientError = ""
	if clientErr != nil {
		m.clientError = clientErr.Error()
	}
	routingDNS.mu.Lock()
	lastError := routingDNS.lastError
	count := len(routingDNS.entries)
	routingDNS.mu.Unlock()
	level, state := 0, "DNS работает"
	if lastError != "" {
		level, state = 1, "Ошибка обновления DNS"
	}
	if m.clientError != "" {
		level, state, lastError = 1, "Не готов DNS для клиентов", m.clientError
	}
	m.setSt(level, true, state, lastError, [2]string{"UDP/TCP", m.address}, [2]string{"Кэш", fmt.Sprint(count)}, [2]string{"IPv6", "AAAA отклоняется; IPv6-маршрутизация не управляется"})
}
func (m *dnsModule) Fields() []Field {
	return []Field{
		fb("dns.loopbackPort", "Порт DNS на loopback", "select", strings.TrimPrefix(dnsAddress(), "127.0.0.1:"), "15353 освобождает порт 5353 для mDNS/WebRTC. DNS клиентов LAN и WG продолжает слушать порт 53.", Opt{"5353", "5353"}, Opt{"15353", "15353"}),
		fb("dns.enabled", "DNS и TTL-кэш", "bool", "true", "Общий выключатель локального и клиентского DNS. Отключение остановит DNS для использующих его клиентов."),
		fb("dns.upstream", "Вышестоящий DNS (IPv4:порт)", "text", "127.0.0.53:53", "По умолчанию системный resolved с настройками MeduzaVPN/провайдера. Кэш обновляет IPv4-адреса доменов в правилах; AAAA локальный прокси отклоняет."),
		fb("dns.serveWG", "DNS для WireGuard-клиентов", "bool", "false", "Адрес сервера WG, порт 53. Запросы принимаются только через WG-интерфейс из его подсети."),
		fb("dns.allowLAN", "Разрешённые LAN-подсети", "textarea", "", "Частные IPv4-подсети через запятую. Требуются для включения DNS на LAN-адресе."),
		fb("dns.lanAddress", "LAN-адрес DNS", "text", "", "Частный IPv4 этого ПК. Пусто — DNS для LAN выключен; служба привязывается к интерфейсу этого адреса."),
	}
}
func (m *dnsModule) Set(key, value string) error {
	if key == "dns.loopbackPort" {
		if value != "5353" && value != "15353" {
			return fmt.Errorf("допустимые порты: 5353 и 15353")
		}
		m.tk.Lock()
		defer m.tk.Unlock()
		addr := "127.0.0.1:" + value
		if m.stop == nil || m.address == addr {
			return setCfg(key, value)
		}
		stop, err := startDNSListener(addr, routingDNS, dnsApplyAnswer)
		if err != nil {
			return err
		}
		if err = setCfg(key, value); err != nil {
			stop()
			return err
		}
		m.stop()
		m.stop, m.address = stop, addr
		return nil
	}
	if key != "dns.enabled" && key != "dns.upstream" && key != "dns.serveWG" && key != "dns.allowLAN" && key != "dns.lanAddress" {
		return errNoField
	}
	value = strings.TrimSpace(value)
	m.tk.Lock()
	defer m.tk.Unlock()
	settings, err := readDNSClientSettings(map[string]string{key: value})
	if err != nil {
		return err
	}
	if key == "dns.allowLAN" {
		value = settings.LANText
	}
	plans, err := settings.plans(Sim)
	if err != nil {
		return err
	}
	if Sim {
		plans = nil
	}
	var staged map[string]*dnsClientListener
	if routingDNS != nil {
		staged, err = m.prepareClients(plans)
		if err != nil {
			return err
		}
	}
	if err := setCfg(key, value); err != nil {
		m.discardClients(staged)
		return err
	}
	if routingDNS != nil {
		m.publishClients(staged, plans)
		m.clientError = ""
		m.tickLocked()
	}
	if routingDNS != nil && (key == "dns.enabled" || key == "dns.upstream") {
		routingDNS.mu.Lock()
		routingDNS.entries = map[string]dnsEntry{}
		routingDNS.retry = map[string]time.Time{}
		routingDNS.generation++
		routingDNS.mu.Unlock()
	}
	if routeAgentRunning && (key == "dns.enabled" || key == "dns.upstream") {
		applySoon("DNS: изменение настроек")
	}
	return nil
}
func (m *dnsModule) Actions() []Action {
	return []Action{{ID: "compare-address", Title: "Сверить адрес клиента с правилом", Args: []Field{{Key: "name", Title: "Домен", Type: "text"}, {Key: "ip", Title: "IPv4 на клиенте", Type: "text"}, {Key: "rule", Title: "Правило", Type: "select"}, {Key: "client", Title: "Адрес DNS-клиента WG/LAN (необязательно)", Type: "text"}}}, {ID: "lookup", Title: "Проверить локальный DNS", Args: []Field{{Key: "name", Title: "Домен", Type: "text", Value: "example.com"}}}, {ID: "wg-profiles", Title: "DNS шлюза в экспортируемых WG-профилях"}}
}
func (m *dnsModule) Do(id string, args map[string]string) (string, error) {
	if id == "compare-address" {
		return compareDNSAddress(args)
	}
	if id == "wg-profiles" {
		m.tk.Lock()
		defer m.tk.Unlock()
		settings, err := readDNSClientSettings(nil)
		if err != nil {
			return "", err
		}
		if !settings.Enabled || !settings.WG || !Sim && (m.clientError != "" || m.clients[net.JoinHostPort(settings.WGAddress, "53")+"@"+settings.WGInterface] == nil) {
			return "", fmt.Errorf("сначала включите и проверьте DNS для WireGuard")
		}
		if err := setCfg("wg.dns", settings.WGAddress); err != nil {
			return "", err
		}
		Decide("INFO", "DNS: экспортируемые WG-профили используют %s; существующие подключения не изменялись", settings.WGAddress)
		return "В экспортируемых WG-профилях DNS = " + settings.WGAddress + ". На уже подключённых устройствах обновите строку DNS или импортируйте профиль заново.", nil
	}
	if id != "lookup" {
		return "", errNoField
	}
	name := dnsName(strings.TrimSpace(args["name"]))
	if !reDomain.MatchString(name) {
		return "", fmt.Errorf("нужен домен без схемы и пути")
	}
	packet, err := dnsRequest(name)
	if err != nil {
		return "", err
	}
	c, err := net.DialTimeout("tcp4", dnsAddress(), time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(packet)))
	if _, err = c.Write(append(size[:], packet...)); err != nil {
		return "", err
	}
	if _, err = io.ReadFull(c, size[:]); err != nil {
		return "", err
	}
	reply := make([]byte, int(binary.BigEndian.Uint16(size[:])))
	if _, err = io.ReadFull(c, reply); err != nil {
		return "", err
	}
	message, err := dnsQuestion(reply, true)
	if err != nil {
		return "", err
	}
	if message.RCode != 0 {
		return "", fmt.Errorf("DNS вернул код %d", message.RCode)
	}
	addresses, _ := dnsAddresses(message, time.Now())
	var rows []string
	for ip, expiry := range addresses {
		rows = append(rows, fmt.Sprintf("%s (TTL до %d с)", ip, max(0, int(time.Until(expiry).Seconds()))))
	}
	sort.Strings(rows)
	if len(rows) == 0 {
		return name + ": IPv4-ответов с положительным TTL нет", nil
	}
	return name + " → " + strings.Join(rows, ", "), nil
}
func (m *dnsModule) Metrics() map[string]float64 {
	if routingDNS == nil {
		return nil
	}
	routingDNS.mu.Lock()
	defer routingDNS.mu.Unlock()
	return map[string]float64{"cache_entries": float64(len(routingDNS.entries)), "queries": float64(routingDNS.queries), "errors": float64(routingDNS.failures), "refused": float64(routingDNS.refused)}
}
func (m *dnsModule) Tables() []Table {
	if routingDNS == nil {
		return nil
	}
	clients := m.clientStatus()
	listenerRows := [][]string{{"Локальный", dnsAddress(), "loopback", "127.0.0.0/8"}}
	for _, listener := range clients["listeners"].([]dnsClientPlan) {
		listenerRows = append(listenerRows, []string{listener.Kind, listener.Address, listener.Interface, listener.Sources})
	}
	routingDNS.mu.Lock()
	defer routingDNS.mu.Unlock()
	now := routingDNS.now()
	var names []string
	for name := range routingDNS.entries {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > 100 {
		names = names[:100]
	}
	var rows [][]string
	for _, name := range names {
		entry := routingDNS.entries[name]
		var values []string
		ttl := 3600
		for ip, expiry := range entry.Addresses {
			if expiry.After(now) {
				values = append(values, ip)
				ttl = min(ttl, int(expiry.Sub(now).Seconds()))
			}
		}
		sort.Strings(values)
		if len(values) == 0 {
			ttl = max(0, int(entry.Until.Sub(now).Seconds()))
		}
		rows = append(rows, []string{name, strings.Join(values, ", "), fmt.Sprint(ttl), entry.Source, entry.Seen.UTC().Format("2006-01-02 15:04:05")})
	}
	return []Table{{Title: "Доступ к DNS", Cols: []string{"Вход", "UDP/TCP", "Интерфейс", "Разрешённые источники"}, Rows: listenerRows, Note: "WG обслуживается только через WireGuard; LAN — из перечисленных подсетей. DNS в экспортируемых WG-профилях: " + clients["wgProfileDNS"].(string) + ". Для уже импортированных профилей обновите строку DNS на устройствах. AAAA отклоняется; IPv6-трафик и DoH/DoT клиентов этим не ограничиваются."}, {Title: "TTL-кэш маршрутизации · первые 100 имён", Cols: []string{"Домен", "IPv4", "Осталось, с", "Последний ответ", "Получен, UTC"}, Rows: rows, Note: "Кэш хранится в памяти: только A из совпадающих с запросом ответов для доменов правил и их поддоменов, до 512 имён и 64 адресов на имя. Записи с TTL=0 не удерживаются. Самостоятельной DNSSEC-валидации нет."}, routingDNS.peerTable()}
}

func dnsErrorReply(packet []byte, code dnsmessage.RCode) []byte {
	var request dnsmessage.Message
	_ = request.Unpack(packet)
	id := request.ID
	if len(packet) >= 2 {
		id = binary.BigEndian.Uint16(packet[:2])
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: id, Response: true, RecursionDesired: request.RecursionDesired, RecursionAvailable: true, RCode: code}, Questions: request.Questions}
	if len(m.Questions) > 1 {
		m.Questions = nil
	}
	reply, _ := m.Pack()
	return reply
}
func (e *dnsEngine) serve(packet []byte, apply func() error) []byte {
	e.mu.Lock()
	generation := e.generation
	e.mu.Unlock()
	request, err := dnsQuestion(packet, false)
	if err != nil {
		return dnsErrorReply(packet, dnsmessage.RCodeFormatError)
	}
	q := request.Questions[0]
	if q.Type == dnsmessage.TypeAAAA || q.Type == 251 || q.Type == 252 || q.Type == 255 {
		e.mu.Lock()
		e.refused++
		e.mu.Unlock()
		return dnsErrorReply(packet, dnsmessage.RCodeRefused)
	}
	reply, err := e.exchange(packet)
	e.mu.Lock()
	e.queries++
	if err != nil {
		e.failures++
		e.lastError = err.Error()
	}
	e.mu.Unlock()
	if err != nil {
		return dnsErrorReply(packet, dnsmessage.RCodeServerFailure)
	}
	m, err := dnsQuestion(reply, true)
	if err != nil || m.ID != request.ID || !sameDNSQuestion(m.Questions[0], q) || m.Truncated {
		return dnsErrorReply(packet, dnsmessage.RCodeServerFailure)
	}
	if q.Type == dnsmessage.TypeA && (m.RCode == 0 || m.RCode == dnsmessage.RCodeNameError) {
		if !e.learn(m, generation, "Запрос через DNS-прокси") {
			return dnsErrorReply(packet, dnsmessage.RCodeServerFailure)
		}
		e.mu.Lock()
		watched := e.watchedLocked(dnsName(q.Name.String()))
		e.mu.Unlock()
		// Новый адрес отдаётся клиенту только после согласования правил.
		if watched && apply != nil {
			if err := apply(); err != nil {
				return dnsErrorReply(packet, dnsmessage.RCodeServerFailure)
			}
		}
	}
	return reply
}

func startDNSListener(address string, e *dnsEngine, apply func() error) (func(), error) {
	udpAddress, err := net.ResolveUDPAddr("udp4", address)
	if err != nil || !udpAddress.IP.IsLoopback() {
		return nil, fmt.Errorf("DNS разрешён только на loopback")
	}
	return startDNSListenerWithAccess(address, "", "", newDNSAccessPolicy(func(ip net.IP) bool { return ip.IsLoopback() }), e, apply)
}
func startDNSListenerWithAccess(address, iface, kind string, policy *dnsAccessPolicy, e *dnsEngine, apply func() error) (func(), error) {
	udpAddress, err := net.ResolveUDPAddr("udp4", address)
	if err != nil || udpAddress.IP.To4() == nil || !udpAddress.IP.IsLoopback() && (!privateIPv4(udpAddress.IP) || iface == "") || policy == nil {
		return nil, fmt.Errorf("DNS: нужен loopback либо частный IPv4 с привязкой к интерфейсу и ACL")
	}
	config, err := dnsListenConfig(iface)
	if err != nil {
		return nil, err
	}
	packet, err := config.ListenPacket(context.Background(), "udp4", address)
	if err != nil {
		return nil, err
	}
	udp, ok := packet.(*net.UDPConn)
	if !ok {
		packet.Close()
		return nil, fmt.Errorf("DNS UDP: неподдерживаемый сокет")
	}
	tcp, err := config.Listen(context.Background(), "tcp4", address)
	if err != nil {
		udp.Close()
		return nil, err
	}
	slots := make(chan struct{}, 32)
	done := make(chan struct{})
	var once sync.Once
	go func() {
		for {
			buffer := make([]byte, 4097)
			n, peer, err := udp.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if n > 4096 {
				continue
			}
			if !policy.allows(peer.IP) {
				continue
			}
			packet := buffer[:n]
			select {
			case slots <- struct{}{}:
				go func() {
					defer func() { <-slots }()
					if !policy.allows(peer.IP) {
						return
					}
					reply := e.serve(packet, apply)
					if len(reply) > 512 {
						request, _ := dnsQuestion(packet, false)
						short := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, RecursionDesired: request.RecursionDesired, RecursionAvailable: true, Truncated: true}, Questions: request.Questions}
						reply, _ = short.Pack()
					}
					select {
					case <-done:
						return
					default:
					}
					if policy.allows(peer.IP) {
						if n, err := udp.WriteToUDP(reply, peer); err == nil && n == len(reply) {
							e.sentDNS(kind, peer.IP.String(), false, reply)
						}
					}
				}()
			default:
			}
		}
	}()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			peer, ok := c.RemoteAddr().(*net.TCPAddr)
			if !ok || !policy.allows(peer.IP) {
				c.Close()
				continue
			}
			select {
			case slots <- struct{}{}:
				go func() {
					defer c.Close()
					defer func() { <-slots }()
					for {
						_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
						var size [2]byte
						if _, err := io.ReadFull(c, size[:]); err != nil {
							return
						}
						n := int(binary.BigEndian.Uint16(size[:]))
						if n < 12 || n > 4096 {
							return
						}
						packet := make([]byte, n)
						if _, err := io.ReadFull(c, packet); err != nil {
							return
						}
						select {
						case <-done:
							return
						default:
						}
						if !policy.allows(peer.IP) {
							return
						}
						reply := e.serve(packet, apply)
						select {
						case <-done:
							return
						default:
						}
						if !policy.allows(peer.IP) {
							return
						}
						binary.BigEndian.PutUint16(size[:], uint16(len(reply)))
						_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
						if written, err := c.Write(append(size[:], reply...)); err != nil || written != len(reply)+2 {
							return
						}
						e.sentDNS(kind, peer.IP.String(), true, reply)
					}
				}()
			default:
				c.Close()
			}
		}
	}()
	return func() { once.Do(func() { close(done); _ = udp.Close(); _ = tcp.Close() }) }, nil
}
