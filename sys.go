// Слой системных команд. Модули обращаются к системе только через Sys:
// в работе это настоящие команды Ubuntu, в режиме имитации (--sim) — модель в sim.go.
package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Sys interface {
	// Run возвращает общий вывод и код выхода (-1 — команду не удалось запустить).
	Run(timeout time.Duration, stdin, name string, args ...string) (string, int)
	// Stream — то же, но каждая строка вывода сразу передаётся в line (для команд, которые долго ждут,
	// например вход по QR). Возвращает код выхода.
	Stream(timeout time.Duration, stdin string, line func(string), name string, args ...string) int
	ReadFile(path string) (string, error)
	WriteFile(path, text string, mode os.FileMode) error
	Remove(path string) error
	List(dir string) []string
	Resolve(host string) []string
}

type realSys struct{}

func (realSys) Run(timeout time.Duration, stdin, name string, args ...string) (string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	err := c.Run()
	if err == nil {
		return out.String(), 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return out.String(), ee.ExitCode()
	}
	return out.String() + err.Error(), -1
}
func (realSys) Stream(timeout time.Duration, stdin string, line func(string), name string, args ...string) int {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	pr, pw := io.Pipe()
	c.Stdout, c.Stderr = pw, pw
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	if err := c.Start(); err != nil {
		line(err.Error())
		return -1
	}
	done := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			line(sc.Text())
		}
		close(done)
	}()
	err := c.Wait()
	pw.Close()
	<-done
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}
func (realSys) ReadFile(p string) (string, error) { b, err := os.ReadFile(p); return string(b), err }
func (realSys) WriteFile(p, t string, m os.FileMode) error {
	return os.WriteFile(p, []byte(t), m)
}
func (realSys) Remove(p string) error { return os.Remove(p) }
func (realSys) List(dir string) []string {
	var out []string
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		if !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}
func (realSys) Resolve(h string) []string {
	var out []string
	ips, _ := net.LookupIP(h)
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	return out
}

func run(name string, args ...string) (string, int) { return S.Run(20*time.Second, "", name, args...) }
func active(unit string) bool {
	out, _ := run("systemctl", "is-active", unit)
	return strings.TrimSpace(out) == "active"
}

// probe — проходит ли трафик через интерфейс: HTTPS-запрос с привязкой к нему.
func probe(iface, url string) bool {
	if iface == "" {
		return false
	}
	ok, _ := probeMs(iface, url)
	return ok
}

// probeMs — то же и время ответа в миллисекундах (для теста протоколов).
func probeMs(iface, url string) (bool, int) {
	if iface == "" {
		return false, -1
	}
	out, _ := S.Run(9*time.Second, "", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}", "--interface", iface, "--max-time", "6", url)
	f := strings.Fields(out)
	if len(f) == 0 || len(f[0]) != 3 || f[0] == "000" {
		return false, -1
	}
	ms := -1
	if len(f) > 1 {
		if v, err := strconv.ParseFloat(f[1], 64); err == nil {
			ms = int(v * 1000)
		}
	}
	return true, ms
}
