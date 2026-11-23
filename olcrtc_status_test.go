package main

import "testing"

func TestOlcClientStatus(t *testing.T) {
	for input, want := range map[string]string{
		"":                                "Нет данных",
		"Connecting transport=vp8channel": "Нет данных",
		"2026/11/23 15:00:00 Current peers count: 0, Devices: []":      "Ожидает клиента",
		"2026/11/23 15:00:00 Current peers count: 2, Devices: [a, b]":  "Подключено клиентов: 2",
		"Server link reported conference end: closed":                  "Связь с комнатой прервана",
		"server reconnect reason=provider - tearing down smux session": "Переподключение: клиент не подтверждён",
	} {
		if got := olcClientStatus(input); got != want {
			t.Errorf("olcClientStatus(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestOlcBytes(t *testing.T) {
	for input, want := range map[string]string{
		"": "—", "[not set]": "—", "18446744073709551615": "—",
		"0": "0 Б", "2048\n": "2.0 КиБ", "1048576": "1.0 МиБ",
	} {
		if got := olcBytes(input); got != want {
			t.Errorf("olcBytes(%q) = %q, want %q", input, got, want)
		}
	}
}
