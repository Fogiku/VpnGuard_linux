package main

import (
	"fmt"
	"strconv"
	"strings"
)

// Назначения остаются стабильными: существующие conntrack-потоки используют их
// после обновления. Новые VPN-модули объявляют уникальную пару Mark/Table в Exit.
type routeResource struct {
	Owner    string `json:"owner"`
	Mark     uint32 `json:"mark"`
	Mask     uint32 `json:"mask"`
	Table    string `json:"table"`
	Priority int    `json:"priority"`
}

func legacyRouteResources() []routeResource {
	return []routeResource{
		{"meduza", 0x11, 0xffffffff, "101", 1101},
		{"awg", 0x12, 0xffffffff, "102", 1102},
		{"zapret", 0x13, 0xffffffff, "main", 1200},
		{"direct", 0x14, 0xffffffff, "main", 1200},
		{"block", 0x1f, 0xffffffff, "", 0},
		{"zapret.raw", 0x40000000, 0x40000000, "main", 1201},
	}
}

func validateRouteResources(resources []routeResource) error {
	if len(resources) < 6 || len(resources) > 103 {
		return fmt.Errorf("неполный или слишком большой реестр маршрутов")
	}
	legacy := legacyRouteResources()
	for i, item := range legacy {
		if resources[i] != item {
			return fmt.Errorf("нельзя менять назначение ресурса %s", item.Owner)
		}
	}
	owners, marks, tables := map[string]bool{}, map[uint32]bool{}, map[string]bool{}
	for i, r := range resources {
		if r.Owner == "" || owners[r.Owner] || marks[r.Mark] {
			return fmt.Errorf("конфликт владельца или метки ресурса %s", r.Owner)
		}
		owners[r.Owner], marks[r.Mark] = true, true
		if i >= len(legacy) {
			table, err := strconv.Atoi(r.Table)
			if err != nil || table < 103 || table > 199 || r.Table != strconv.Itoa(table) || r.Mark < 0x20 || r.Mark > 0xfe || r.Mask != 0xffffffff || r.Priority != 1000+table {
				return fmt.Errorf("ресурс %s: новые VPN используют таблицы 103..199 и метки 0x20..0xfe", r.Owner)
			}
		}
		if r.Table != "main" && r.Table != "" {
			if tables[r.Table] {
				return fmt.Errorf("конфликт таблицы %s", r.Table)
			}
			tables[r.Table] = true
		}
	}
	return nil
}

func currentRouteResources() ([]routeResource, error) {
	resources := legacyRouteResources()
	seen := map[string]bool{}
	for _, m := range Mods {
		if m.ID() == "zapret.raw" {
			return nil, fmt.Errorf("ID zapret.raw зарезервирован для raw-пакетов")
		}
		if seen[m.ID()] {
			return nil, fmt.Errorf("повторный ID модуля %s", m.ID())
		}
		seen[m.ID()] = true
		e := m.Exit()
		if e == nil {
			continue
		}
		var existing *routeResource
		for i := range resources {
			if resources[i].Owner == m.ID() {
				existing = &resources[i]
				break
			}
		}
		table := "main"
		if e.Table != 0 {
			table = strconv.Itoa(e.Table)
		}
		if e.Block {
			table = ""
		}
		if existing != nil {
			if e.Mark < 0 || uint32(e.Mark) != existing.Mark || table != existing.Table || (m.ID() == "block") != e.Block {
				return nil, fmt.Errorf("модуль %s изменил закреплённые сетевые ресурсы", m.ID())
			}
		} else {
			if e.Mark < 0 || uint64(e.Mark) > 0xffffffff {
				return nil, fmt.Errorf("неверная метка %s", m.ID())
			}
			resources = append(resources, routeResource{m.ID(), uint32(e.Mark), 0xffffffff, table, 1000 + e.Table})
		}
	}
	return resources, validateRouteResources(resources)
}

func resourceTables(resources []routeResource) []string {
	var tables []string
	for _, r := range resources {
		if r.Table != "" && r.Table != "main" {
			tables = append(tables, r.Table)
		}
	}
	return tables
}

func parseFWMark(value string) (mark, mask uint32, ok bool) {
	rawMark, rawMask, masked := strings.Cut(value, "/")
	m, err := strconv.ParseUint(rawMark, 0, 32)
	if err != nil {
		return 0, 0, false
	}
	if !masked {
		return uint32(m), 0xffffffff, true
	}
	n, err := strconv.ParseUint(rawMask, 0, 32)
	return uint32(m), uint32(n), err == nil
}

func resourceRule(line string, resources []routeResource) ([]string, bool) {
	f := strings.Fields(line)
	if len(f) != 7 || f[1] != "from" || f[2] != "all" || f[3] != "fwmark" || f[5] != "lookup" {
		return nil, false
	}
	priority, err := strconv.Atoi(strings.TrimSuffix(f[0], ":"))
	if err != nil {
		return nil, false
	}
	mark, mask, ok := parseFWMark(f[4])
	if !ok {
		return nil, false
	}
	table := f[6]
	if table == "254" {
		table = "main"
	}
	for _, r := range resources {
		if r.Priority != 0 && priority == r.Priority && mark == r.Mark && mask == r.Mask && table == r.Table {
			return append([]string{"priority", strconv.Itoa(priority)}, f[1:]...), true
		}
	}
	return nil, false
}

// Check foreign selectors before including an additional exit in a recovery snapshot.
// Numeric output makes named routing tables visible under their registered IDs too.
func checkAdditionalRouteUse(resources []routeResource, rules, routes string) error {
	extras := resources[len(legacyRouteResources()):]
	if len(extras) == 0 {
		return nil
	}
	hasOwnRule := map[string]bool{}
	for _, line := range strings.Split(rules, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		priority, err := strconv.Atoi(strings.TrimSuffix(fields[0], ":"))
		if err != nil {
			return fmt.Errorf("не удалось прочитать приоритет правила IPv4")
		}
		for _, r := range extras {
			if _, own := resourceRule(line, []routeResource{r}); own {
				if hasOwnRule[r.Table] {
					return fmt.Errorf("VPN %s: правило с приоритетом %d продублировано", r.Owner, priority)
				}
				hasOwnRule[r.Table] = true
				continue
			}
			if priority == r.Priority {
				return fmt.Errorf("VPN %s: приоритет %d уже занят другим правилом", r.Owner, priority)
			}
			for i := 1; i+1 < len(fields); i++ {
				if fields[i] == "fwmark" {
					mark, mask, ok := parseFWMark(fields[i+1])
					if !ok {
						return fmt.Errorf("не удалось прочитать fwmark правила %d", priority)
					}
					if (mark^r.Mark)&mask&r.Mask == 0 {
						return fmt.Errorf("VPN %s: метка %#x пересекается с fwmark правила %d", r.Owner, r.Mark, priority)
					}
				}
				if (fields[i] == "lookup" || fields[i] == "table") && fields[i+1] == r.Table {
					return fmt.Errorf("VPN %s: таблицу %s использует другое правило", r.Owner, r.Table)
				}
			}
		}
	}
	for _, line := range strings.Split(routes, "\n") {
		fields := strings.Fields(line)
		for i := 1; i+1 < len(fields); i++ {
			if fields[i] != "table" {
				continue
			}
			for _, r := range extras {
				if fields[i+1] == r.Table && (!hasOwnRule[r.Table] || fields[0] != "default") {
					return fmt.Errorf("VPN %s: таблица %s уже содержит сторонний маршрут", r.Owner, r.Table)
				}
			}
		}
	}
	return nil
}
