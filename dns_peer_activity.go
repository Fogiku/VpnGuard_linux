package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"vpnguard/internal/dnsmessage"
)

const dnsPeerLimit, dnsPeerNames = 64, 4

type dnsPeerKey struct{ Kind, IP string }
type dnsSentAnswer struct {
	name      string
	at        time.Time
	addresses map[string]time.Time
}
type dnsPeerStats struct {
	last                                   time.Time
	udp, tcp, refused, servfail, truncated uint64
	answers                                []dnsSentAnswer // newest first, one full A response per tracked name
}

// Called only after the listener writes a complete reply. The peer is the DNS
// requester seen by the socket, which may itself be a forwarding router.
func (e *dnsEngine) sentDNS(kind, ip string, tcp bool, reply []byte) {
	if kind == "" || len(reply) < 12 {
		return
	}
	msg, err := dnsQuestion(reply, true)
	if err != nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	key := dnsPeerKey{kind, ip}
	peer := e.peers[key]
	if peer == nil {
		if e.peers == nil {
			e.peers = make(map[dnsPeerKey]*dnsPeerStats)
		}
		if len(e.peers) >= dnsPeerLimit {
			var oldest dnsPeerKey
			for k, v := range e.peers {
				if oldest.Kind == "" || v.last.Before(e.peers[oldest].last) {
					oldest = k
				}
			}
			delete(e.peers, oldest)
		}
		peer = &dnsPeerStats{}
		e.peers[key] = peer
	}
	peer.last = now
	if tcp {
		peer.tcp++
	} else {
		peer.udp++
	}
	if msg.Truncated {
		peer.truncated++
		return
	}
	switch msg.RCode {
	case dnsmessage.RCodeRefused:
		peer.refused++
		return
	case dnsmessage.RCodeServerFailure:
		peer.servfail++
		return
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
	default:
		return
	}
	q := msg.Questions[0]
	name := dnsName(q.Name.String())
	if q.Type != dnsmessage.TypeA || !e.watchedLocked(name) {
		return
	}
	ips, _ := dnsAddresses(msg, now)
	if msg.RCode != dnsmessage.RCodeSuccess {
		ips = nil
	}
	answers := []dnsSentAnswer{{name, now, ips}}
	for _, old := range peer.answers {
		if old.name != name && len(answers) < dnsPeerNames {
			answers = append(answers, old)
		}
	}
	peer.answers = answers
}

// Called under e.mu from the DNS page snapshot.
func (e *dnsEngine) peerTable() Table {
	t := Table{Title: "Ответы DNS клиентам", Cols: []string{"Вход", "Клиент", "UDP", "TCP", "REFUSED", "SERVFAIL", "Усечено", "Последний ответ, UTC"},
		Empty: "Ответов клиентам WG или LAN пока не наблюдалось", Note: "Счётчики отправленных ответов с начала наблюдения за источником. До 64 источников в памяти; при заполнении вытесняется самый давно наблюдавшийся. Если запрос переслал роутер, здесь виден его адрес."}
	for k, p := range e.peers {
		row := []string{k.Kind, k.IP}
		for _, count := range []uint64{p.udp, p.tcp, p.refused, p.servfail, p.truncated} {
			row = append(row, strconv.FormatUint(count, 10))
		}
		t.Rows = append(t.Rows, append(row, p.last.UTC().Format(time.RFC3339)))
	}
	sort.Slice(t.Rows, func(i, j int) bool {
		if t.Rows[i][0] != t.Rows[j][0] {
			return t.Rows[i][0] < t.Rows[j][0]
		}
		return t.Rows[i][1] < t.Rows[j][1]
	})
	return t
}

func (e *dnsEngine) peerCoverage(client, name, ip string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var lines []string
	now := e.now()
	for k, p := range e.peers {
		if k.IP != client {
			continue
		}
		for _, ans := range p.answers {
			if ans.name != name {
				continue
			}
			detail := "совпадение IPv4 не подтверждено"
			if expiry, ok := ans.addresses[ip]; ok {
				detail = "этот IPv4 был отправлен, учтённый TTL истёк"
				if expiry.After(now) {
					detail = fmt.Sprintf("этот IPv4 отправлен, остаток TTL %d с", int(expiry.Sub(now).Seconds()))
				}
			}
			lines = append(lines, fmt.Sprintf("%s %s · %s: %s", k.Kind, client, ans.at.UTC().Format(time.RFC3339), detail))
		}
	}
	if len(lines) == 0 {
		return "нет сохранённого полного A-ответа для этой пары клиент/домен"
	}
	sort.Strings(lines)
	return strings.Join(lines, "; ")
}
