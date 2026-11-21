package main

import "testing"

func TestModuleStatusOwnsDetails(t *testing.T) {
	var module base
	want := [2]string{"link", "up"}
	rows := [][2]string{want}
	module.setSt(0, true, "ready", "", rows...)

	rows[0][1] = "publisher changed"
	first := module.Status()
	if first.KV[0] != want {
		t.Errorf("publisher changed stored status: %v", first.KV)
	}
	first.KV[0][1] = "reader changed"
	if next := module.Status(); next.KV[0] != want {
		t.Errorf("reader changed stored status: %v", next.KV)
	}
}
