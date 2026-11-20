//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
)

func lockRouteFiles() (func(), error) {
	f, err := os.OpenFile(filepath.Join(DataDir, "routes.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
func syncRouteDirectory() error {
	f, err := os.Open(DataDir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
