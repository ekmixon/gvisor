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

// This package should only be used for go>=1.10 because of
// https://github.com/golang/go/issues/20676
//go:build linux && go1.10
// +build linux,go1.10

// Package dut provides common definitions and utilities to be shared by DUTs.
package dut

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

var (
	// CtrlIface is the name of the control interface.
	CtrlIface = ""
	// TestIface is the name of the test interface.
	TestIface = ""
)

const (
	// completeFd is used for notifying the parent for the completion of setup.
	completeFd = 3
	// dutNSFd is the network namespace the DUT should live in.
	dutNSFd = 4
	// PosixServerPort is the port the posix server should listen on.
	PosixServerPort = 54321
)

// Init puts the current process into the target network namespace, the user of
// this library should call this function in the beginning.
func Init() {
	// If we are called for the first time, we re-exec to enter the namespace.
	if os.Args[0] != "/proc/self/exe" {
		if err := func() error {
			runtime.LockOSThread()
			defer runtime.LockOSThread()
			// The file descriptor is no longer useful after we enter the namespace.
			syscall.CloseOnExec(dutNSFd)
			if err := unix.Setns(dutNSFd, unix.CLONE_NEWNET); err != nil {
				return fmt.Errorf("failed to switch to DUT namespace: %w", err)
			}
			if err := syscall.Exec("/proc/self/exe", append([]string{"/proc/self/exe"}, os.Args[1:]...), os.Environ()); err != nil {
				return fmt.Errorf("failed to re-exec self in DUT namespace: %w", err)
			}
			return nil
		}(); err != nil {
			log.Fatal(err)
		}
	}
	// The DUT might create child processes, we don't want this fd to leak into
	// those processes as it keeps the pipe open and the testbench will hang
	// waiting for an EOF on the pipe.
	syscall.CloseOnExec(completeFd)
	// Register command line flags.
	flag.StringVar(&CtrlIface, "ctrl_iface", "", "the name of the control interface")
	flag.StringVar(&TestIface, "test_iface", "", "the name of the test interface")
}

// DUT is an interface for different platforms of DUTs.
type DUT interface {
	// Bootstrap starts and waits for the completion of DUT. It will write into
	// infoCh when DUT is in an state that is ready for the test.
	Bootstrap(ctx context.Context, infoCh chan<- testbench.DUTInfo) error
	// Cleanup stops the DUT and cleans up the resources being used.
	Cleanup()
}

// Bootstrap is the provided function that calls its Bootstrap and Cleanup
// methods and returns the DUT information to the parent through the pipe.
func Bootstrap(dut DUT) error {
	if !flag.Parsed() {
		flag.Parse()
	}
	defer dut.Cleanup()

	// Register for cleanup signals.
	stopSigs := make(chan os.Signal, 1)
	signal.Notify(stopSigs, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(stopSigs)

	// Start bootstrapping the DUT.
	infoCh := make(chan testbench.DUTInfo, 1)
	g, ctx := errgroup.WithContext(context.Background())
	g.Go(func() error {
		return dut.Bootstrap(ctx, infoCh)
	})

	for {
		select {
		// We have successfully set up the device.
		case info := <-infoCh:
			bytes, err := json.Marshal(info)
			if err != nil {
				return fmt.Errorf("failed to marshal dut info into json: %w", err)
			}
			// Send the DUT information to the parent through the pipe.
			completeFile := os.NewFile(completeFd, "complete")
			for len(bytes) > 0 {
				n, err := completeFile.Write(bytes)
				if err != nil && err != io.ErrShortWrite {
					return fmt.Errorf("write(%d) = %d, %w", completeFile.Fd(), n, err)
				}
				bytes = bytes[n:]
			}
			if err := completeFile.Close(); err != nil {
				return fmt.Errorf("close(%d) = %w", completeFile.Fd(), err)
			}
		// An error occurred in the DUT.
		case <-ctx.Done():
			return fmt.Errorf("failed to bootstrap DUT: %w", g.Wait())
		// An signal occurred, we should exit.
		case <-stopSigs:
			return nil
		}
	}
}

// waitForServer waits for a pattern to occur in posix_server's logs.
func waitForServer(output io.Reader) {
	scanner := bufio.NewScanner(output)
	for scanner.Scan() {
		if text := scanner.Text(); strings.HasPrefix(text, "Server listening on") {
			log.Printf("posix_server: %s", text)
			return
		}
	}
}

// StartPosixServer starts a posix_server command and returns a channel that
// will be written when server starts listening.
func StartPosixServer(cmd *exec.Cmd) (<-chan struct{}, error) {
	// The posix_server emits logs in stderr.
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe to the posix server process: %w", err)
	}

	done := make(chan struct{}, 1)
	go func() {
		waitForServer(errPipe)
		done <- struct{}{}
	}()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start the posix server process: %w", err)
	}
	return done, nil
}
