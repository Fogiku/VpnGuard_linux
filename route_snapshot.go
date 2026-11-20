package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Снимок содержит только ресурсы VpnGuard. Правила MeduzaVPN и main не меняем.
type routeSnapshot struct {
	nft       string
	rules     [][]string
	defaults  map[string][]string
	resources []routeResource
}

type routeSnapshotData struct {
	NFT       string              `json:"nft"`
	Rules     [][]string          `json:"rules"`
	Defaults  map[string][]string `json:"defaults"`
	Resources []routeResource     `json:"resources,omitempty"`
}

func (s routeSnapshot) MarshalJSON() ([]byte, error) {
	return json.Marshal(routeSnapshotData{s.nft, s.rules, s.defaults, s.resources})
}
func (s *routeSnapshot) UnmarshalJSON(b []byte) error {
	var d routeSnapshotData
	if err := json.Unmarshal(b, &d); err != nil {
		return err
	}
	if d.Resources == nil {
		d.Resources = legacyRouteResources()
	}
	if err := validateRouteResources(d.Resources); err != nil {
		return err
	}
	s.nft, s.rules, s.defaults, s.resources = d.NFT, d.Rules, d.Defaults, d.Resources
	return nil
}

func ownedRule(line string) ([]string, bool) {
	return resourceRule(line, legacyRouteResources())
}

func snapshotRoutes() (*routeSnapshot, error) {
	resources, err := currentRouteResources()
	if err != nil {
		return nil, err
	}
	s := &routeSnapshot{defaults: map[string][]string{}, resources: resources}
	// Отсутствие таблицы отличается от ошибки доступа к ядру.
	out, code := run("nft", "list", "tables")
	if code != 0 {
		return nil, fmt.Errorf("снимок nft: %s", out)
	}
	if strings.Contains(out, "table inet vpnguard\n") || strings.TrimSpace(out) == "table inet vpnguard" {
		s.nft, code = run("nft", "list", "table", "inet", "vpnguard")
		if code != 0 {
			return nil, fmt.Errorf("снимок таблицы nft: %s", s.nft)
		}
	}
	out, code = run("ip", "-4", "-o", "rule", "show")
	if code != 0 {
		return nil, fmt.Errorf("снимок ip rule: %s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if args, ok := resourceRule(line, resources); ok {
			s.rules = append(s.rules, args)
		}
	}
	// show table all работает и при отсутствии частной таблицы.
	out, code = run("ip", "-4", "-o", "route", "show", "table", "all")
	if code != 0 {
		return nil, fmt.Errorf("снимок маршрутов: %s", out)
	}
	s.defaults = resourceDefaults(out, resources)
	return s, nil
}

func ownedDefaults(out string) map[string][]string {
	return resourceDefaults(out, legacyRouteResources())
}
func resourceDefaults(out string, resources []routeResource) map[string][]string {
	defaults := map[string][]string{}
	for _, table := range resourceTables(resources) {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) < 3 || f[0] != "default" {
				continue
			}
			for i := 1; i+1 < len(f); i++ {
				if f[i] == "table" && f[i+1] == table {
					var replay []string
					for _, token := range f {
						if token != "linkdown" {
							replay = append(replay, token)
						}
					}
					defaults[table] = append(defaults[table], strings.Join(replay, " "))
				}
			}
		}
	}
	return defaults
}

func (s *routeSnapshot) restore() error {
	resources := s.resources
	if resources == nil {
		resources = legacyRouteResources()
	}
	if err := validateRouteResources(resources); err != nil {
		return err
	}
	var failures []string
	exec := func(name string, args ...string) {
		if out, code := run(name, args...); code != 0 {
			failures = append(failures, fmt.Sprintf("%s %v: %s", name, args, out))
		}
	}
	// Сначала таблицы и правила, затем соответствующие им метки nft.
	current, routeCode := run("ip", "-4", "-o", "route", "show", "table", "all")
	if routeCode != 0 {
		return fmt.Errorf("откат: чтение маршрутов: %s", current)
	}
	currentDefaults := resourceDefaults(current, resources)
	for _, table := range resourceTables(resources) {
		if strings.Join(currentDefaults[table], "\n") == strings.Join(s.defaults[table], "\n") {
			continue
		}
		if len(currentDefaults[table]) > 0 {
			exec("ip", "-4", "route", "flush", "table", table, "default")
		}
		for _, line := range s.defaults[table] {
			exec("ip", append([]string{"-4", "route", "add"}, strings.Fields(line)...)...)
		}
	}
	out, code := run("ip", "-4", "-o", "rule", "show")
	if code != 0 {
		failures = append(failures, "не удалось прочитать ip rule при откате")
	} else {
		for _, line := range strings.Split(out, "\n") {
			if args, ok := resourceRule(line, resources); ok {
				exec("ip", append([]string{"-4", "rule", "del"}, args...)...)
			}
		}
	}
	for _, args := range s.rules {
		exec("ip", append([]string{"-4", "rule", "add"}, args...)...)
	}
	script := "table inet vpnguard\ndelete table inet vpnguard\n" + s.nft
	if out, code := S.Run(20*time.Second, script, "nft", "-f", "-"); code != 0 {
		failures = append(failures, "nft: "+out)
	}
	if len(failures) > 0 {
		return fmt.Errorf("откат: %s", strings.Join(failures, "; "))
	}
	return nil
}
