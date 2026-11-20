package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServerAndClientWithoutPresharedKey(t *testing.T) {
	setup(t)
	c := wgMod.d.Clients[0]
	c.Psk = ""
	conf := wgMod.conf(false)
	if _, _, _, _, _, _, err := wgMod.parseServerConf(conf); err != nil {
		t.Fatalf("server generated an invalid config without PSK: %v", err)
	}
	if strings.Contains(wgMod.clientConf(c), "PresharedKey") {
		t.Fatal("client without PSK must omit the option")
	}
}

func TestImportPreservesDisabledClients(t *testing.T) {
	setup(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wg_server.conf"), []byte(wgMod.conf(false)), 0600); err != nil {
		t.Fatal(err)
	}
	ip := wgMod.d.Clients[0].IP
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"wg":{"clientOff":["`+ip+`"]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := importWindows(dir); err != nil {
		t.Fatal(err)
	}
	if !wgMod.d.Clients[0].Off {
		t.Fatal("disabled Windows peer must remain disabled")
	}
}

func TestSaveJSONReportsFilesystemFailure(t *testing.T) {
	setup(t)
	DataDir = filepath.Join(t.TempDir(), "missing")
	if err := saveJSON("wg.json", wgMod.d); err == nil {
		t.Fatal("missing output directory must return an error")
	}
	if err := setCfg("probe", "value"); err == nil {
		t.Fatal("config write failure must return an error")
	}
	if cfg("probe", "") != "" {
		t.Fatal("failed write must roll back the in-memory value")
	}
}

type captureRouteSys struct {
	Sys
	commands []string
}

func (s *captureRouteSys) Run(d time.Duration, in, name string, args ...string) (string, int) {
	if name == "ip" {
		s.commands = append(s.commands, strings.Join(args, " "))
	}
	return s.Sys.Run(d, in, name, args...)
}

func TestApplyUpdatesChangedInterfaceWithSameNftRules(t *testing.T) {
	sim := setup(t)
	spy := &captureRouteSys{Sys: sim}
	S = spy
	oldApplied, oldIP := applied, appliedIP
	defer func() { applied, appliedIP = oldApplied, oldIP }()
	applied, appliedIP = "", ""
	if err := Apply("first"); err != nil {
		t.Fatal(err)
	}
	spy.commands = nil
	if err := setCfg("awg.active", "awg1"); err != nil {
		t.Fatal(err)
	}
	if err := Apply("interface changed"); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range spy.commands {
		if strings.Contains(c, "route replace default dev awg1 table 102") {
			found = true
		}
	}
	if !found {
		t.Fatal("changed AWG interface must update its route even with identical nft text")
	}
}
