package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInboundOlcClientLifecycle(t *testing.T) {
	setup(t)
	m := inboundOlc
	if !hasPage(m) || m.Exit() != nil {
		t.Fatal("inbound server visibility")
	}
	args := map[string]string{"name": "laptop", "room": "https://meet.example.org/my-laptop"}
	if _, err := m.Do("add", args); err != nil {
		t.Fatal(err)
	}
	for _, a := range []map[string]string{args, {"name": "phone", "room": args["room"]}, {"name": "../x", "room": args["room"]}, {"name": "phone", "room": "ftp://host/x"}} {
		if _, err := m.Do("add", a); err == nil {
			t.Fatal("accepted invalid or duplicate profile")
		}
	}
	profile, err := m.clientConfig("laptop")
	if err != nil {
		t.Fatal(err)
	}
	var c olcConfig
	if err = json.Unmarshal([]byte(profile), &c); err != nil || c.Mode != "cnc" || c.Socks == nil || c.Socks.Port != 8808 {
		t.Fatal("invalid client export")
	}
	srv, err := readOlcPeer("laptop")
	if err != nil || srv.Crypto.Key != c.Crypto.Key || srv.Room != c.Room || srv.Mode != "srv" || srv.Socks != nil {
		t.Fatal("mismatched server and client")
	}
	st, err := os.Stat(filepath.Join(olcDir(), "laptop.yaml"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("profile permissions")
	}
	public, _ := json.Marshal(buildState())
	if strings.Contains(string(public), c.Crypto.Key) {
		t.Fatal("key leaked in state")
	}
	row := map[string]string{"row": "laptop"}
	for _, action := range []string{"start", "stop", "start", "remove"} {
		if _, err = m.Do(action, row); err != nil {
			t.Fatal(err)
		}
		if active(olcUnit("laptop")) != (action == "start") {
			t.Fatal(action)
		}
	}
	if _, err = m.clientConfig("laptop"); err == nil {
		t.Fatal("revoked profile still available")
	}
}

func TestOlcRoomForEachDevice(t *testing.T) {
	setup(t)
	rooms := map[string]bool{}
	for _, name := range []string{"phone", "tablet"} {
		if err := createOlcPeer(name, "jitsi", "https://meet.example.org/"); err != nil {
			t.Fatal(err)
		}
		c, err := readOlcPeer(name)
		if err != nil || !strings.HasPrefix(c.Room.ID, "https://meet.example.org/vpnguard-") || rooms[c.Room.ID] {
			t.Fatal("expected a distinct room on the selected server", err)
		}
		rooms[c.Room.ID] = true
	}
}

func TestOlcProviderProfiles(t *testing.T) {
	setup(t)
	for _, tc := range []struct{ provider, room string }{
		{"telemost", "https://telemost.yandex.ru/j/123456"},
		{"wbstream", "123456"},
	} {
		_, err := inboundOlc.Do("add", map[string]string{"name": tc.provider, "provider": tc.provider, "room": tc.room})
		if err != nil {
			t.Fatal(err)
		}
		server, err := readOlcPeer(tc.provider)
		if err != nil {
			t.Fatal(err)
		}
		profile, err := inboundOlc.clientConfig(tc.provider)
		if err != nil {
			t.Fatal(err)
		}
		var client olcConfig
		if err := json.Unmarshal([]byte(profile), &client); err != nil {
			t.Fatal(err)
		}
		for _, c := range []olcConfig{server, client} {
			if c.Auth.Provider != tc.provider || c.Room.ID != "123456" || c.Net.Transport != "vp8channel" {
				t.Fatal("wrong provider configuration")
			}
		}
	}
}
