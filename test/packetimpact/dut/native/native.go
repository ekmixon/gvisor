// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux && go1.10
// +build linux,go1.10

// For bringing up a native linux DUT.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/test/packetimpact/dut"
	"gvisor.dev/gvisor/test/packetimpact/dut/linux"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

var _ dut.DUT = (*native)(nil)

type native struct{}

func main() {
	dut.Init()
	if err := dut.Bootstrap(&native{}); err != nil {
		log.Fatal(err)
	}
}

// Bootstrap implements dut.DUT
func (*native) Bootstrap(ctx context.Context, infoCh chan<- testbench.DUTInfo) error {
	// Enable ICMP sockets.
	if err := os.WriteFile("/proc/sys/net/ipv4/ping_group_range", []byte("0 0"), 0); err != nil {
		return fmt.Errorf("failed to enable icmp sockets: %w", err)
	}
	// Find the posix_server binary.
	path, err := testutil.FindFile("test/packetimpact/dut/posix_server")
	if err != nil {
		return fmt.Errorf("failed to find the posix_server binary: %w", err)
	}
	cmd := exec.CommandContext(ctx, path, "--ip", "0.0.0.0", "--port", fmt.Sprintf("%d", dut.PosixServerPort))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: unix.SIGKILL,
	}
	done, err := dut.StartPosixServer(cmd)
	if err != nil {
		return err
	}
	select {
	case <-done:
		info, err := linux.DUTInfo()
		if err != nil {
			return fmt.Errorf("failed to collect information about the DUT: %w", err)
		}
		infoCh <- info
	case <-ctx.Done():
		return fmt.Errorf("bootstrap context cancelled before posix server is ready: %w", ctx.Err())
	}
	return cmd.Wait()
}

// Bootstrap implements dut.DUT
func (n *native) Cleanup() {
	// For a native DUT case, we only need to cleanup the posix_server process which we set up to
	// deliver a SIGKILL signal whenever we exit, so there is nothing to do here.
}
