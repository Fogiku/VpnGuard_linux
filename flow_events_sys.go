package main

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"strings"
)

// Optional Sys capability. Context cancellation kills and reaps the Python child.
func (realSys) FlowEvents(ctx context.Context, program string, line func(string) error) error {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(childCtx, "python3", "-")
	cmd.Stdin = strings.NewReader(program)
	cmd.Stderr = io.Discard // Do not leak addresses/payloads via error logging.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 65536), 1<<20)
	for scanner.Scan() {
		if err = line(scanner.Text()); err != nil {
			cancel()
			break
		}
	}
	if err == nil {
		err = scanner.Err()
	}
	if err != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	if err != nil {
		return err
	}
	return waitErr
}
