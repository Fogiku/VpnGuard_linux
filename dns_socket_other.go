//go:build !linux

package main

import (
	"fmt"
	"net"
)

func dnsListenConfig(iface string) (net.ListenConfig, error) {
	if iface != "" {
		return net.ListenConfig{}, fmt.Errorf("привязка клиентского DNS к интерфейсу доступна в Linux")
	}
	return net.ListenConfig{}, nil
}
