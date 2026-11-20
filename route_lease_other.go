//go:build !linux

package main

func lockRouteFiles() (func(), error) { return func() {}, nil }
func syncRouteDirectory() error       { return nil }
