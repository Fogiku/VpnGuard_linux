//go:build linux

package main

import (
	"net"
	"syscall"
)

func dnsListenConfig(iface string) (net.ListenConfig, error) {
	config := net.ListenConfig{}
	if iface != "" {
		config.Control = func(network, address string, raw syscall.RawConn) error {
			var optionError error
			err := raw.Control(func(fd uintptr) {
				optionError = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
			})
			if err != nil {
				return err
			}
			return optionError
		}
	}
	return config, nil
}
