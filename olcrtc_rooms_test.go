package main

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type olcRoomTransport func(*http.Request) (*http.Response, error)

func (f olcRoomTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRequestOlcRoom(t *testing.T) {
	for _, tc := range []struct {
		provider, host, authorization, body, response, want string
	}{
		{"telemost", "cloud-api.yandex.net", "OAuth sample", `{"waiting_room_level":"PUBLIC"}`, `{"join_url":"https://telemost.yandex.ru/j/12345"}`, "12345"},
		{"wbstream", "stream.wb.ru", "Bearer sample", `{"roomType":"ROOM_TYPE_ALL_ON_SCREEN","roomPrivacy":"ROOM_PRIVACY_FREE"}`, `{"roomId":"wb-room"}`, "wb-room"},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			client := &http.Client{Transport: olcRoomTransport(func(req *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(req.Body)
				if err != nil || string(body) != tc.body || req.URL.Host != tc.host ||
					req.Method != http.MethodPost || req.Header.Get("Authorization") != tc.authorization {
					t.Fatal("unexpected room creation request")
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tc.response))}, nil
			})}
			got, err := requestOlcRoom(client, tc.provider, "sample")
			if err != nil || got != tc.want {
				t.Fatalf("room = %q, err = %v", got, err)
			}
		})
	}
}

func TestOlcRoomRequestErrorDoesNotExposeToken(t *testing.T) {
	client := &http.Client{Transport: olcRoomTransport(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("sample-secret")
	})}
	_, err := requestOlcRoom(client, "wbstream", "sample-secret")
	if err == nil || strings.Contains(err.Error(), "sample-secret") {
		t.Fatalf("unexpected error: %v", err)
	}
}
