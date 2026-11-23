package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const assignmentFile = "route-assignments.json"

type routeRegistry struct {
	active   []routeResource // Only these resources may enter a recovery snapshot.
	reserved []routeResource // Includes absent owners whose connections may still exist.
}

// The last 1.9.3 snapshot is a migration source for previously registered VPNs.
func loadRouteAssignments() ([]routeResource, bool, error) {
	b, err := os.ReadFile(filepath.Join(DataDir, assignmentFile))
	if os.IsNotExist(err) {
		last, err := readRouteChange(routeLastFile)
		if os.IsNotExist(err) {
			return legacyRouteResources(), false, nil
		}
		if err != nil {
			return nil, false, err
		}
		return last.Before.resources, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var entries []routeResource
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, false, fmt.Errorf("%s: %w", assignmentFile, err)
	}
	return entries, true, validateRouteResources(entries)
}

type occupiedVPNResources struct {
	marks  map[uint32]bool
	tables map[string]bool
}

// A new owner cannot adopt even an identical pre-existing kernel rule.
func occupiedVPNs(saved []routeResource, rules, routes string) (occupiedVPNResources, error) {
	used := occupiedVPNResources{map[uint32]bool{}, map[string]bool{"198": true}} // Priority 1198 belongs to the site probe.
	for _, r := range saved {
		used.marks[r.Mark], used.tables[r.Table] = true, true
	}
	for _, line := range strings.Split(rules, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		p, err := strconv.Atoi(strings.TrimSuffix(f[0], ":"))
		if err != nil {
			return used, fmt.Errorf("не удалось прочитать приоритет правила IPv4")
		}
		used.tables[strconv.Itoa(p-1000)] = true
		for i := 1; i+1 < len(f); i++ {
			switch f[i] {
			case "lookup", "table":
				used.tables[f[i+1]] = true
			case "fwmark":
				m, mask, ok := parseFWMark(f[i+1])
				if !ok {
					return used, fmt.Errorf("не удалось прочитать fwmark правила %d", p)
				}
				for candidate := uint32(0x20); candidate <= 0xfe; candidate++ {
					if (candidate^m)&mask == 0 {
						used.marks[candidate] = true
					}
				}
			}
		}
	}
	for _, line := range strings.Split(routes, "\n") {
		f := strings.Fields(line)
		for i := 1; i+1 < len(f); i++ {
			if f[i] == "table" {
				used.tables[f[i+1]] = true
			}
		}
	}
	return used, nil
}

func (u occupiedVPNResources) allocate(id string) (routeResource, error) {
	m := uint32(0x20)
	for ; m <= 0xfe && u.marks[m]; m++ {
	}
	t := 103
	for ; t <= 199 && u.tables[strconv.Itoa(t)]; t++ {
	}
	if m > 0xfe || t > 199 {
		return routeResource{}, fmt.Errorf("VPN %s: нет свободной метки или таблицы маршрутизации", id)
	}
	table := strconv.Itoa(t)
	u.marks[m], u.tables[table] = true, true
	return routeResource{id, m, 0xffffffff, table, 1000 + t}, nil
}

func readIPv4Routing() (rules, routes string, err error) {
	rules, code := run("ip", "-4", "-N", "-o", "rule", "show")
	if code != 0 {
		return "", "", fmt.Errorf("чтение правил IPv4: %s", rules)
	}
	routes, code = run("ip", "-4", "-N", "-o", "route", "show", "table", "all")
	if code != 0 {
		return "", "", fmt.Errorf("чтение таблиц IPv4: %s", routes)
	}
	return rules, routes, nil
}

// Only routeOperation requests allocation, under the same lease as journal recovery.
// UI, telemetry and previews can read existing assignments without reserving numbers.
func resolveRouteRegistry(allocate bool) (reg routeRegistry, err error) {
	saved, exists, err := loadRouteAssignments()
	if err != nil {
		return reg, err
	}
	initial := len(saved)
	owners := make(map[string]routeResource, initial)
	for _, r := range saved {
		owners[r.Owner] = r
	}
	seen := map[string]bool{"zapret.raw": true}
	active := map[string]bool{}
	var pending []string
	for _, m := range Mods {
		if !olcVisible(m) {
			continue
		}
		id := m.ID()
		if id == "" || seen[id] {
			return reg, fmt.Errorf("пустой, повторный или зарезервированный ID модуля %q", id)
		}
		seen[id] = true
		e := m.Exit()
		if e == nil {
			continue
		}
		active[id] = true
		old, known := owners[id]
		if e.AutoRoutes {
			if e.Block || e.Queue || e.Table != 0 || e.Mark != 0 || known && old.Mark < 0x20 {
				return reg, fmt.Errorf("некорректный запрос автоматического назначения для %s", id)
			}
			if !known {
				pending = append(pending, id)
			}
			continue
		}
		table := "main"
		if e.Table != 0 {
			table = strconv.Itoa(e.Table)
		}
		if e.Block {
			table = ""
		}
		if e.Mark < 0 || uint64(e.Mark) > 0xffffffff || (id == "block") != e.Block {
			return reg, fmt.Errorf("неверное объявление выхода %s", id)
		}
		if known {
			if old.Mark != uint32(e.Mark) || old.Table != table {
				return reg, fmt.Errorf("модуль %s изменил закреплённые сетевые ресурсы", id)
			}
		} else {
			saved = append(saved, routeResource{id, uint32(e.Mark), 0xffffffff, table, 1000 + e.Table})
		}
	}
	if err := validateRouteResources(saved); err != nil {
		return reg, err
	}
	if len(pending) > 0 && !allocate {
		return reg, fmt.Errorf("VPN %s ожидает назначения сетевых ресурсов", pending[0])
	}
	var rules, routes string
	if allocate && (len(pending) > 0 || len(saved) > initial || !exists && len(saved) > len(legacyRouteResources())) {
		rules, routes, err = readIPv4Routing()
		if err != nil {
			return reg, err
		}
		used, err := occupiedVPNs(saved, rules, routes)
		if err != nil {
			return reg, err
		}
		sort.Strings(pending)
		for _, id := range pending {
			r, err := used.allocate(id)
			if err != nil {
				return reg, err
			}
			saved = append(saved, r)
		}
	}
	reg.reserved = saved
	reg.active = legacyRouteResources()
	for _, r := range saved[len(reg.active):] {
		if active[r.Owner] {
			reg.active = append(reg.active, r)
		}
	}
	if allocate && (!exists || len(saved) > initial) {
		if err := checkAdditionalRouteUse(reg.active, rules, routes); err != nil {
			return reg, err
		}
		if err := saveJSON(assignmentFile, saved); err != nil {
			return reg, err
		}
		err = syncRouteDirectory()
	}
	return reg, err
}

func currentRouteResources() ([]routeResource, error) {
	reg, err := resolveRouteRegistry(false)
	return reg.active, err
}
