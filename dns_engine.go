package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"vpnguard/internal/dnsmessage"
)

type dnsEntry struct {
	Addresses map[string]time.Time
	Until     time.Time
	Seen      time.Time
}
type dnsEngine struct {
	mu                sync.Mutex
	entries           map[string]dnsEntry
	tracked           map[string]time.Time
	retry             map[string]time.Time
	now               func() time.Time
	exchange          func([]byte) ([]byte, error)
	queries, failures uint64
	refused           uint64
	generation        uint64
	lastError         string
}

var routingDNS *dnsEngine

func newDNSEngine(exchange func([]byte) ([]byte, error)) *dnsEngine {
	return &dnsEngine{entries: map[string]dnsEntry{}, tracked: map[string]time.Time{}, retry: map[string]time.Time{}, now: time.Now, exchange: exchange}
}
func dnsName(name string) string        { return strings.ToLower(strings.TrimSuffix(name, ".")) }
func dnsMatches(name, root string) bool { return name == root || strings.HasSuffix(name, "."+root) }
func (e *dnsEngine) watchedLocked(name string) bool {
	for root := range e.tracked {
		if dnsMatches(name, root) {
			return true
		}
	}
	return false
}

func dnsRequest(name string) ([]byte, error) {
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, err
	}
	var id [2]byte
	if _, err = rand.Read(id[:]); err != nil {
		return nil, err
	}
	return (&dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
}
func dnsQuestion(packet []byte, response bool) (dnsmessage.Message, error) {
	var m dnsmessage.Message
	if len(packet) > 65535 || len(packet) < 12 {
		return m, fmt.Errorf("неверный размер DNS")
	}
	var p dnsmessage.Parser
	header, err := p.Start(packet)
	if err != nil {
		return m, err
	}
	if header.Truncated && response {
		questions, err := p.AllQuestions()
		if err != nil {
			return m, err
		}
		m = dnsmessage.Message{Header: header, Questions: questions}
	} else {
		if err := m.Unpack(packet); err != nil {
			return m, err
		}
	}
	if m.Response != response || m.OpCode != 0 || len(m.Questions) != 1 || m.Questions[0].Class != dnsmessage.ClassINET {
		return m, fmt.Errorf("нужен один обычный DNS-запрос IN")
	}
	return m, nil
}
func sameDNSQuestion(a, b dnsmessage.Question) bool {
	return dnsName(a.Name.String()) == dnsName(b.Name.String()) && a.Type == b.Type && a.Class == b.Class
}

// Учитываем только A из answer и цепочку CNAME, начинающуюся с вопроса.
// Не используем glue/additional, неподтверждённые имена и адреса с TTL=0.
func dnsAddresses(m dnsmessage.Message, now time.Time) (map[string]time.Time, time.Time) {
	addresses := map[string]time.Time{}
	until := now
	if m.Truncated || (m.RCode != dnsmessage.RCodeSuccess && m.RCode != dnsmessage.RCodeNameError) || len(m.Questions) != 1 || m.Questions[0].Type != dnsmessage.TypeA {
		return addresses, until
	}
	name := dnsName(m.Questions[0].Name.String())
	pathTTL := uint32(3600)
	visited := map[string]bool{}
	for hop := 0; hop < 16; hop++ {
		if visited[name] {
			break
		}
		visited[name] = true
		var next string
		nextTTL := pathTTL
		for _, r := range m.Answers {
			if r.Header.Class != dnsmessage.ClassINET || dnsName(r.Header.Name.String()) != name {
				continue
			}
			switch body := r.Body.(type) {
			case *dnsmessage.CNAMEResource:
				next = dnsName(body.CNAME.String())
				nextTTL = min(nextTTL, r.Header.TTL)
			case *dnsmessage.AResource:
				ttl := min(pathTTL, r.Header.TTL)
				if ttl == 0 || len(addresses) >= 64 {
					continue
				}
				ip := net.IP(body.A[:])
				if ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
					continue
				}
				expiry := now.Add(time.Duration(ttl) * time.Second)
				key := ip.String()
				if old, ok := addresses[key]; !ok || expiry.Before(old) {
					addresses[key] = expiry
				}
			}
		}
		if next == "" {
			break
		}
		name, pathTTL = next, nextTTL
	}
	for _, expiry := range addresses {
		if until.Equal(now) || expiry.Before(until) {
			until = expiry
		}
	}
	if len(addresses) == 0 {
		for _, r := range m.Authorities {
			if soa, ok := r.Body.(*dnsmessage.SOAResource); ok && r.Header.Class == dnsmessage.ClassINET {
				zone := dnsName(r.Header.Name.String())
				if zone != "" && !dnsMatches(dnsName(m.Questions[0].Name.String()), zone) {
					continue
				}
				ttl := min(r.Header.TTL, soa.MinTTL, uint32(60))
				expiry := now.Add(time.Duration(ttl) * time.Second)
				if until.Equal(now) || expiry.Before(until) {
					until = expiry
				}
			}
		}
	}
	return addresses, until
}

func (e *dnsEngine) learn(m dnsmessage.Message, generation uint64) bool {
	if len(m.Questions) != 1 || m.Questions[0].Type != dnsmessage.TypeA || m.Truncated || (m.RCode != 0 && m.RCode != dnsmessage.RCodeNameError) {
		return false
	}
	name := dnsName(m.Questions[0].Name.String())
	now := e.now()
	addresses, until := dnsAddresses(m, now)
	e.mu.Lock()
	defer e.mu.Unlock()
	if generation != e.generation {
		return false
	}
	if !e.watchedLocked(name) {
		return true
	}
	if _, exists := e.entries[name]; !exists && len(e.entries) >= 512 {
		var oldest string
		var seen time.Time
		for key, value := range e.entries {
			if _, root := e.tracked[key]; root {
				continue
			}
			if oldest == "" || value.Seen.Before(seen) {
				oldest, seen = key, value.Seen
			}
		}
		if oldest == "" {
			return true
		}
		delete(e.entries, oldest)
	}
	// Старые ответы CDN нужны клиентам до их собственного срока, даже при ротации.
	for ip, expiry := range e.entries[name].Addresses {
		if expiry.After(now) {
			if next, ok := addresses[ip]; ok {
				if expiry.After(next) {
					addresses[ip] = expiry
				}
			} else if len(addresses) < 64 {
				addresses[ip] = expiry
			}
		}
	}
	e.entries[name] = dnsEntry{addresses, until, now}
	delete(e.retry, name)
	return true
}
func (e *dnsEngine) query(name string) error {
	e.mu.Lock()
	generation := e.generation
	e.mu.Unlock()
	packet, err := dnsRequest(name)
	if err == nil {
		var reply []byte
		reply, err = e.exchange(packet)
		if err == nil {
			var m dnsmessage.Message
			m, err = dnsQuestion(reply, true)
			request, _ := dnsQuestion(packet, false)
			if err == nil && (m.ID != request.ID || !sameDNSQuestion(m.Questions[0], request.Questions[0]) || m.Truncated) {
				err = fmt.Errorf("DNS-ответ не соответствует запросу")
			}
			if err == nil && m.RCode != 0 && m.RCode != dnsmessage.RCodeNameError {
				err = fmt.Errorf("DNS вернул код %d", m.RCode)
			}
			if err == nil {
				if !e.learn(m, generation) {
					err = fmt.Errorf("настройки DNS изменились во время запроса")
				}
			}
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.queries++
	if err != nil {
		e.failures++
		e.lastError = err.Error()
		e.retry[name] = e.now().Add(5 * time.Second)
	} else {
		e.lastError = ""
		if entry := e.entries[name]; !entry.Until.After(e.now()) {
			e.retry[name] = e.now().Add(5 * time.Second)
		}
	}
	return err
}

func (e *dnsEngine) lookup(name string) []string {
	name = dnsName(name)
	if !reDomain.MatchString(name) {
		return nil
	}
	now := e.now()
	e.mu.Lock()
	_, known := e.tracked[name]
	if !known && len(e.tracked) >= 256 {
		e.lastError = "лимит 256 доменов маршрутизации"
		e.mu.Unlock()
		return nil
	}
	e.tracked[name] = now
	fresh := e.entries[name].Until.After(now) || e.retry[name].After(now)
	e.mu.Unlock()
	if !fresh {
		_ = e.query(name)
	}
	now = e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	set := map[string]bool{}
	for key, entry := range e.entries {
		if dnsMatches(key, name) {
			for ip, expiry := range entry.Addresses {
				if expiry.After(now) {
					set[ip] = true
				}
			}
		}
	}
	ips := make([]string, 0, len(set))
	for ip := range set {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips
}

func (e *dnsEngine) refresh() {
	now := e.now()
	e.mu.Lock()
	var roots []string
	for name, seen := range e.tracked {
		if now.Sub(seen) > 15*time.Minute {
			delete(e.tracked, name)
			delete(e.retry, name)
			continue
		}
		if !e.entries[name].Until.After(now) && !e.retry[name].After(now) {
			roots = append(roots, name)
		}
	}
	changed := false
	for name, entry := range e.entries {
		for ip, expiry := range entry.Addresses {
			if !expiry.After(now) {
				delete(entry.Addresses, ip)
				if e.watchedLocked(name) {
					changed = true
				}
			}
		}
		if len(entry.Addresses) == 0 && now.Sub(entry.Seen) > time.Hour {
			delete(e.entries, name)
		}
	}
	e.mu.Unlock()
	for _, name := range roots {
		_ = e.query(name)
		changed = true
	}
	if changed && routeAgentRunning && !routesStarting.Load() {
		applySoon("DNS: обновление адресов и TTL")
	}
}

func validDNSUpstream(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	p, err := strconv.Atoi(port)
	return err == nil && p > 0 && p <= 65535 && strconv.Itoa(p) == port && ip != nil && ip.To4() != nil && !strings.Contains(host, ":") && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.Equal(net.IPv4bcast) && !(ip.IsLoopback() && (p == 5353 || p == 15353))
}

// Используем DNS systemd-resolved, сохраняя выбор DNS MeduzaVPN и провайдера.
func exchangeDNS(packet []byte) ([]byte, error) {
	upstream := cfg("dns.upstream", "127.0.0.53:53")
	if !validDNSUpstream(upstream) {
		return nil, fmt.Errorf("нужен IPv4-адрес DNS и числовой порт; петля к прокси запрещена")
	}
	request, err := dnsQuestion(packet, false)
	if err != nil {
		return nil, err
	}
	if Sim {
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, RecursionAvailable: true, RecursionDesired: request.RecursionDesired}, Questions: request.Questions}
		if request.Questions[0].Type == dnsmessage.TypeA {
			for _, value := range S.Resolve(dnsName(request.Questions[0].Name.String())) {
				if ip := net.ParseIP(value).To4(); ip != nil {
					var a [4]byte
					copy(a[:], ip)
					m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: request.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: a}})
				}
			}
		}
		return m.Pack()
	}
	query := append([]byte(nil), packet...)
	var nonce [2]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	copy(query[:2], nonce[:])
	c, err := net.DialTimeout("udp4", upstream, time.Second)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = c.Write(query)
	reply := make([]byte, 65535)
	var n int
	if err == nil {
		n, err = c.Read(reply)
	}
	c.Close()
	if err != nil {
		return nil, err
	}
	reply = reply[:n]
	validate := func(data []byte) (dnsmessage.Message, error) {
		m, err := dnsQuestion(data, true)
		if err == nil && (m.ID != binary.BigEndian.Uint16(nonce[:]) || !sameDNSQuestion(m.Questions[0], request.Questions[0])) {
			err = fmt.Errorf("DNS-ответ не соответствует запросу")
		}
		return m, err
	}
	m, err := validate(reply)
	if err != nil {
		return nil, err
	}
	if m.Truncated {
		c, err = net.DialTimeout("tcp4", upstream, time.Second)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(query)))
		_, err = c.Write(append(size[:], query...))
		if err == nil {
			_, err = io.ReadFull(c, size[:])
		}
		if err != nil {
			return nil, err
		}
		n = int(binary.BigEndian.Uint16(size[:]))
		if n < 12 {
			return nil, fmt.Errorf("неполный TCP DNS-ответ")
		}
		reply = make([]byte, n)
		if _, err = io.ReadFull(c, reply); err != nil {
			return nil, err
		}
		if m, err = validate(reply); err != nil || m.Truncated {
			return nil, fmt.Errorf("неполный или неверный TCP DNS-ответ")
		}
	}
	binary.BigEndian.PutUint16(reply[:2], request.ID)
	return reply, nil
}
