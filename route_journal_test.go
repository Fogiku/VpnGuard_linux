package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRouteConfirmationIsBoundToRequester(t *testing.T) {
	transactionSetup(t)
	if err := setNetworkPolicyFrom("net.pinFlows", "true", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	pending := pendingRouteView()
	if pending == nil {
		t.Fatal("confirmation checkpoint missing")
	}
	if err := confirmRouteChangeFrom(pending.ID, "127.0.0.1"); err == nil {
		t.Fatal("another address confirmed the change")
	}
	if err := Apply("concurrent event"); err == nil {
		t.Fatal("unconfirmed operation overwritten")
	}
	if err := confirmRouteChangeFrom(pending.ID, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if pendingRouteView() != nil {
		t.Fatal("confirmed operation still pending")
	}
	if _, err := readRouteChange(routeLastFile); err != nil {
		t.Fatal("persistent rollback checkpoint missing", err)
	}
}

type journalOrderSys struct {
	Sys
	t    *testing.T
	seen bool
}

func (s *journalOrderSys) Run(d time.Duration, input, name string, args ...string) (string, int) {
	if name == "nft" && len(args) == 2 && args[0] == "-f" {
		change, err := readRouteChange(routePendingFile)
		if err != nil || !change.KernelChanged || change.Before == nil {
			s.t.Fatalf("mutation without durable journal: %v", err)
		}
		s.seen = true
	}
	return s.Sys.Run(d, input, name, args...)
}
func TestJournalPrecedesKernelMutation(t *testing.T) {
	transactionSetup(t)
	spy := &journalOrderSys{Sys: S, t: t}
	S = spy
	if err := Apply("ordered mutation"); err != nil {
		t.Fatal(err)
	}
	if !spy.seen {
		t.Fatal("kernel mutation not observed")
	}
	if _, err := os.Stat(filepath.Join(DataDir, routePendingFile)); !os.IsNotExist(err) {
		t.Fatal("automatic operation did not finalize")
	}
}

func TestStartupRecoveryRestoresNetworkKeysOnly(t *testing.T) {
	transactionSetup(t)
	if err := setCfg("unrelated", "keep"); err != nil {
		t.Fatal(err)
	}
	if err := setNetworkPolicy("net.pinFlows", "true"); err != nil {
		t.Fatal(err)
	}
	if err := setCfg("unrelated", "new-value"); err != nil {
		t.Fatal(err)
	}
	if err := recoverRoutesOnStartup(); err != nil {
		t.Fatal(err)
	}
	if cfgBool("net.pinFlows", false) || cfg("unrelated", "") != "new-value" {
		t.Fatal("recovery changed unrelated settings or retained candidate policy")
	}
	if pendingRouteView() != nil {
		t.Fatal("recovered marker not cleared")
	}
}

func TestLoadConfigRemovesDeletedKeys(t *testing.T) {
	DataDir = t.TempDir()
	cfgMap = map[string]string{"deleted": "old"}
	b, _ := json.Marshal(map[string]string{"kept": "value"})
	if err := saveFile("config.json", b); err != nil {
		t.Fatal(err)
	}
	loadCfg()
	if cfg("deleted", "") != "" || cfg("kept", "") != "value" {
		t.Fatal("config reload retained deleted keys")
	}
}

func TestProfileRenameDoesNotChangeKernel(t *testing.T) {
	s := transactionSetup(t)
	if err := Apply("baseline"); err != nil {
		t.Fatal(err)
	}
	s.commands = nil
	b, _ := json.Marshal(rt)
	var next Routes
	json.Unmarshal(b, &next)
	next.Profiles[0].Name = "renamed"
	if err := setRoutes(next); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range s.commands {
		if cmd == "nft -f -" || strings.HasPrefix(cmd, "ip rule add") || strings.HasPrefix(cmd, "ip route replace") {
			t.Fatal("rename mutated kernel", cmd)
		}
	}
	c, err := readRouteChange(routePendingFile)
	if err != nil || c.KernelChanged {
		t.Fatal("rename recorded a kernel mutation", err)
	}
}
