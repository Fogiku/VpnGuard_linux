package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

type mdzLocation struct {
	Key, Group, City, Label string
	Recommended, Warning    bool
}

func locationName(raw any) string {
	names, _ := raw.([]any)
	for _, language := range []string{"ru", "en", ""} {
		for _, item := range names {
			n, _ := item.(map[string]any)
			if strings.HasPrefix(strings.ToLower(pickStr(n, "lang")), language) {
				if label := pickStr(n, "name"); label != "" {
					return label
				}
			}
		}
	}
	return ""
}

var locationNumber = regexp.MustCompile(`[\s_-]+[0-9]+$`)

func parseMeduzaLocations(data any) []mdzLocation {
	groups, _ := data.([]any)
	var result []mdzLocation
	seen := map[string]bool{}
	for _, raw := range groups {
		group, _ := raw.(map[string]any)
		groupID := pickStr(group, "id")
		if groupID == "" {
			continue
		}
		country := locationName(group["names"])
		if country == "" {
			country = pickStr(group, "flag")
		}
		packages, _ := group["packages"].([]any)
		for _, rawPackage := range packages {
			p, _ := rawPackage.(map[string]any)
			pricing, _ := p["pricing"].([]any)
			if len(pricing) == 0 {
				continue
			}
			if location, ok := p["location"].(string); ok && location == "" {
				continue
			}
			city := pickStr(p, "city_id")
			if city == "" {
				names, _ := p["names"].([]any)
				for _, n := range names {
					d, _ := n.(map[string]any)
					if strings.HasPrefix(strings.ToLower(pickStr(d, "lang")), "en") {
						city = pickStr(d, "name")
						break
					}
				}
				if city == "" {
					city = locationName(p["names"])
				}
				if city == "" {
					city = pickStr(p, "location", "id")
				}
				city = strings.ToLower(strings.Join(strings.Fields(locationNumber.ReplaceAllString(strings.TrimSpace(city), "")), " "))
			}
			if city == "" {
				continue
			}
			key := groupID + ":" + city
			label := locationName(p["city_names"])
			if label == "" {
				label = locationNumber.ReplaceAllString(locationName(p["names"]), "")
			}
			if label == "" {
				label = city
			}
			recommended, _ := group["recommended"].(bool)
			warning, _ := p["ru_warning"].(bool)
			if seen[key] {
				for i := range result {
					if result[i].Key == key && !warning {
						result[i].Warning = false
					}
				}
				continue
			}
			seen[key] = true
			result = append(result, mdzLocation{key, groupID, city, country + " — " + label, recommended, warning})
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Recommended != result[j].Recommended {
			return result[i].Recommended
		}
		if result[i].Warning != result[j].Warning {
			return !result[i].Warning
		}
		return result[i].Label < result[j].Label
	})
	return result
}

// Keep the account token on the gateway; never pass it to the browser or a CLI argument.
var meduzaAccountClient = &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func meduzaAccountRequest(client *http.Client, token, method, endpoint string, payload any) (map[string]any, int, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, 0, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, 0, errors.New("Не удалось подготовить запрос MeduzaVPN")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return nil, 0, errors.New("API MeduzaVPN недоступно, повторите позже")
	}
	defer res.Body.Close()
	var answer map[string]any
	err = json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(&answer)
	if res.StatusCode < 200 || res.StatusCode >= 300 || err != nil || pickStr(answer, "status") != "success" {
		message := pickStr(answer, "message")
		if message == "" {
			message = "операция не выполнена"
		}
		return nil, res.StatusCode, fmt.Errorf("MeduzaVPN (HTTP %d): %s", res.StatusCode, firstLine(message))
	}
	return answer, res.StatusCode, nil
}
func (m *meduza) accountAPI(method, path string, payload any) (map[string]any, error) {
	for attempt := 0; attempt < 2; attempt++ {
		raw, err := S.ReadFile("/var/lib/meduzavpn/session.json")
		if err != nil {
			return nil, errors.New("Сессия MeduzaVPN не найдена, выполните вход")
		}
		var session map[string]any
		if json.Unmarshal([]byte(raw), &session) != nil || pickStr(session, "access_token") == "" {
			return nil, errors.New("Сессия MeduzaVPN недоступна, выполните вход")
		}
		result, status, err := meduzaAccountRequest(meduzaAccountClient, pickStr(session, "access_token"), method, "https://api.meduzavpn.com/api"+path, payload)
		// Reads can refresh an expired session through the supported CLI. Never replay a change request.
		if status == 401 && method == http.MethodGet && attempt == 0 {
			m.cli("list", "--services", "--json")
			continue
		}
		return result, err
	}
	return nil, errors.New("Сессия MeduzaVPN истекла, выполните вход")
}
func (m *meduza) locationService() (string, error) {
	service := cfg("meduza.serviceId", "")
	for _, item := range m.services {
		if item.ID == service {
			return service, nil
		}
	}
	if service == "" && len(m.services) == 1 {
		return m.services[0].ID, nil
	}
	return "", errors.New("Сначала выберите VPN в разделе «Подключение» и обновите список VPN")
}
func (m *meduza) availableLocations(service string) ([]mdzLocation, error) {
	response, err := m.accountAPI(http.MethodGet, "/services/"+url.PathEscape(service)+"/available-locations", nil)
	if err != nil {
		return nil, err
	}
	locations := parseMeduzaLocations(response["data"])
	if len(locations) == 0 {
		return nil, errors.New("MeduzaVPN не предлагает других локаций для этого VPN")
	}
	return locations, nil
}
func (m *meduza) locationAction() (Action, error) {
	service, err := m.locationService()
	if err != nil {
		return Action{}, err
	}
	locations, err := m.availableLocations(service)
	if err != nil {
		return Action{}, err
	}
	options := []Opt{{V: "", T: "Выберите страну и город"}}
	for _, item := range locations {
		label := item.Label
		if item.Recommended {
			label += " · рекомендовано MeduzaVPN"
		}
		if item.Warning {
			label += " · возможны проблемы доступа из РФ"
		}
		options = append(options, Opt{V: item.Key, T: label})
	}
	return Action{ID: "change-location", Title: "Сменить локацию", Confirm: "MeduzaVPN перенесёт этот VPN в выбранную локацию. Связь на всех его устройствах прервётся обычно на 1–2 минуты, затем шлюз переподключится.", Args: []Field{
		{Key: "service", Title: "VPN", Type: "select", Value: service, Options: []Opt{{V: service, T: service}}},
		{Key: "location", Title: "Страна и город", Type: "select", Value: "", Options: options},
	}}, nil
}
func (m *meduza) changeLocation(args map[string]string) (string, error) {
	if !m.locationChange.TryLock() {
		return "", errors.New("Запрос смены локации уже выполняется")
	}
	defer m.locationChange.Unlock()
	service, err := m.locationService()
	if err != nil {
		return "", err
	}
	if args["service"] != service {
		return "", errors.New("Выбранный VPN изменился. Откройте выбор локации заново")
	}
	locations, err := m.availableLocations(service)
	if err != nil {
		return "", err
	}
	var selected *mdzLocation
	for i := range locations {
		if locations[i].Key == args["location"] {
			selected = &locations[i]
			break
		}
	}
	if selected == nil {
		return "", errors.New("Выберите доступную страну и город")
	}
	m.lmu.Lock()
	pending := time.Now().Before(m.locationUntil)
	m.lmu.Unlock()
	if pending {
		return "", errors.New("Смена локации уже выполняется, подождите")
	}
	_, err = m.accountAPI(http.MethodPost, "/services/"+url.PathEscape(service)+"/change-location", map[string]string{"group_id": selected.Group, "city_id": selected.City})
	if err != nil {
		return "", err
	}
	m.lmu.Lock()
	m.locationUntil = time.Now().Add(90 * time.Second)
	m.lmu.Unlock()
	m.cli("disconnect")
	m.catAt = time.Time{}
	Decide("INFO", "MeduzaVPN: запрошена смена локации VPN %s → %s", service, selected.Label)
	go m.Tick()
	return "MeduzaVPN принял смену локации: " + selected.Label + ". Ожидайте 1–2 минуты; шлюз переподключится автоматически.", nil
}
