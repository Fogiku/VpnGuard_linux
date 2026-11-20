package main

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

func parseLocalNetworks(value string) ([]string, error) {
	seen := map[string]bool{}
	var result []string
	for _, token := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' || r == '\t' }) {
		ip, network, err := net.ParseCIDR(token)
		if err != nil || ip.To4() == nil {
			return nil, fmt.Errorf("локальная сеть %q: нужна IPv4-подсеть, например 192.168.1.0/24", token)
		}
		prefix, _ := network.Mask.Size()
		if prefix == 0 {
			return nil, errors.New("маршрут 0.0.0.0/0 нельзя использовать как локальную сеть")
		}
		canonical := network.String()
		if !seen[canonical] {
			seen[canonical] = true
			result = append(result, canonical)
		}
	}
	sort.Strings(result)
	return result, nil
}

func setNetworkPolicy(key, value string) error {
	return setNetworkPolicyFrom(key, value, "")
}
func setNetworkPolicyFrom(key, value, requester string) error {
	if key == "net.localNetworks" {
		networks, err := parseLocalNetworks(value)
		if err != nil {
			return err
		}
		value = strings.Join(networks, ", ")
	} else if key == "net.pinFlows" {
		if value != "true" && value != "false" {
			return errors.New("нужно true или false")
		}
	} else {
		return errNoField
	}
	applyMu.Lock()
	defer applyMu.Unlock()
	cfgMu.Lock()
	old, had := cfgMap[key]
	cfgMu.Unlock()
	if had && old == value {
		return nil
	}
	return routeOperation("изменение сетевой политики", true, true, func() error {
		activeRouteChange.Requester = requester
		if _, err := ensureRouteJournal(); err != nil {
			return err
		}
		if err := setCfg(key, value); err != nil {
			return err
		}
		return applyLocked("изменение сетевой политики")
	})
}
