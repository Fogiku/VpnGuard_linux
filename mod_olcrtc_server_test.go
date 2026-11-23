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
