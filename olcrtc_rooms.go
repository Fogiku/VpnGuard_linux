package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var olcRoomClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func requestOlcRoom(client *http.Client, provider, token string) (string, error) {
	var service, endpoint, auth, body string
	switch provider {
	case "telemost":
		service = "Яндекс Телемост"
		endpoint = "https://cloud-api.yandex.net/v1/telemost-api/conferences"
		auth = "OAuth"
		body = `{"waiting_room_level":"PUBLIC"}`
	case "wbstream":
		service = "WB Stream"
		endpoint = "https://stream.wb.ru/api-room/api/v2/room"
		auth = "Bearer"
		body = `{"roomType":"ROOM_TYPE_ALL_ON_SCREEN","roomPrivacy":"ROOM_PRIVACY_FREE"}`
	default:
		return "", errors.New("неизвестный сервис olcRTC")
	}
	if token == "" || len(token) > 8192 || strings.IndexFunc(token, func(r rune) bool { return r <= ' ' || r >= 127 }) >= 0 {
		return "", fmt.Errorf("%s: введите действующий токен", service)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", auth+" "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s: не удалось связаться с API создания встреч", service)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return "", fmt.Errorf("%s: проверьте токен и право создания встреч (HTTP %d)", service, resp.StatusCode)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return "", fmt.Errorf("%s: API не создал встречу (HTTP %d)", service, resp.StatusCode)
	}
	var result struct {
		JoinURL string `json:"join_url"`
		RoomID  string `json:"roomId"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result); err != nil {
		return "", fmt.Errorf("%s: API вернул некорректный ответ", service)
	}
	room := result.RoomID
	if provider == "telemost" {
		room = result.JoinURL
		if !strings.HasPrefix(room, "https://telemost.yandex.ru/j/") {
			return "", fmt.Errorf("%s: API не вернул ссылку на встречу", service)
		}
	}
	return olcRoomID(provider, room)
}
