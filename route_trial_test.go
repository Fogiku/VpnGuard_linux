package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRouteTrialModel(t *testing.T) {
	setup(t)
	ip := wgMod.Clients()[0].IP
	before, _ := json.Marshal(rt)
	for _, exit := range []string{"meduza", "direct"} {
		trial, err := planRouteTrial(ip, exit)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(trial.NFT, "elements = { "+ip+" }") || !strings.Contains(trial.NFT, `comment "trial_default"`) {
			t.Fatal("missing trial classifier")
		}
		res, err := previewRoute(ip, exit)
		if err != nil || res["mode"] != "simulator" {
			t.Fatalf("simulator: %v, %v", res, err)
		}
	}
	after, _ := json.Marshal(rt)
	if string(before) != string(after) {
		t.Fatal("live model changed")
	}
	if _, err := planRouteTrial("192.0.2.14", "direct"); err == nil {
		t.Fatal("unknown client accepted")
	}
	if _, err := planRouteTrial(ip, "bogus"); err == nil {
		t.Fatal("unknown exit accepted")
	}
}

func TestRouteTrialCompiledKernel(t *testing.T) {
	if os.Getenv("VPNGUARD_TEST_ROUTE_TRIAL") != "1" {
		t.Skip("requires isolated Linux kernel with CAP_SYS_ADMIN")
	}
	setup(t)
	parent, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	for _, exit := range []string{"meduza", "direct"} {
		trial, err := planRouteTrial(wgMod.Clients()[0].IP, exit)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(trial)
		if err != nil {
			t.Fatal(err)
		}
		out, code := (realSys{}).Run(30*time.Second, string(data), "unshare", "--net", "--", "python3", "-I", "-c", routeTrialWorker, parent)
		if code != 0 || strings.TrimSpace(out) != "verified" {
			t.Fatalf("%s: %d %s", exit, code, out)
		}
	}
}

func TestExitFailureForecast(t *testing.T) {
	setup(t)
	available := map[string]bool{"meduza": true, "awg": true, "direct": true}
	policy := ExitPolicy{Reserve: "awg", IfDown: "block"}
	result := forecastExit("meduza", policy, available)
	if result["current"] != "meduza" || result["primaryDown"] != "awg" || result["bothDown"] != "block" {
		t.Fatal(result)
	}
	policy.IfDown = "direct"
	if got := forecastExit("meduza", policy, available)["bothDown"]; got != "direct" {
		t.Fatal(got)
	}
	policy.Reserve = "direct"
	if got := forecastExit("meduza", policy, available)["bothDown"]; got != "block" {
		t.Fatal(got)
	}
	if !available["direct"] || !available["meduza"] || !available["awg"] {
		t.Fatal("status snapshot mutated")
	}
}
