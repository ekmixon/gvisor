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

//go:build linux
// +build linux

// For bringing up a gVisor DUT.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/test/packetimpact/dut"
	"gvisor.dev/gvisor/test/packetimpact/dut/linux"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

type runsc struct {
	containerID      string
	runscPath        string
	runscLogsPath    string
	bundleDir        string
	rootDir          string
	cleanupRootDir   func()
	cleanupBundleDir func()
}

var _ dut.DUT = (*runsc)(nil)

func main() {
	dut.Init()
	// Find the path to the binaries.
	posixServerPath, err := testutil.FindFile("test/packetimpact/dut/posix_server")
	if err != nil {
		log.Fatalf("failed to find posix_server binary: %s", err)
	}
	runscPath, err := testutil.FindFile("runsc/runsc")
	if err != nil {
		log.Fatalf("failed to find runsc binary: %s", err)
	}

	// Create the OCI spec for the container with posix_server as the entrypoint.
	spec := testutil.NewSpecWithArgs(posixServerPath, "--ip", "0.0.0.0", "--port", fmt.Sprintf("%d", dut.PosixServerPort))
	pwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("failed to get the current working directory: %s", err)
	}
	spec.Process.Cwd = pwd
	if spec.Linux == nil {
		spec.Linux = &specs.Linux{}
	}
	// Use the DUT namespace which is ours.
	spec.Linux.Namespaces = append(spec.Linux.Namespaces, specs.LinuxNamespace{
		Type: "network",
		Path: fmt.Sprintf("/proc/%d/ns/net", os.Getpid()),
	})

	// Enable ICMP sockets.
	if spec.Linux.Sysctl == nil {
		spec.Linux.Sysctl = make(map[string]string)
	}
	spec.Linux.Sysctl["/proc/sys/net/ipv4/ping_group_range"] = "0 0"

	// Prepare logs.
	runscLogPath, err := undeclaredOutput("runsc.%%TIMESTAMP%%.%%COMMAND%%.log")
	if err != nil {
		log.Fatalf("failed to create runsc log file: %s", err)
	}

	// Build the command to start runsc container.
	bundleDir, cleanupBundleDir, err := testutil.SetupBundleDir(spec)
	if err != nil {
		log.Fatalf("failed to create bundle dir: %s", err)
	}
	rootDir, cleanupRootDir, err := testutil.SetupRootDir()
	if err != nil {
		cleanupBundleDir()
		log.Fatalf("SetupRootDir failed: %v", err)
	}
	if err := dut.Bootstrap(&runsc{
		containerID:      testutil.RandomContainerID(),
		runscPath:        runscPath,
		runscLogsPath:    runscLogPath,
		bundleDir:        bundleDir,
		rootDir:          rootDir,
		cleanupRootDir:   cleanupRootDir,
		cleanupBundleDir: cleanupBundleDir,
	}); err != nil {
		log.Fatal(err)
	}
}

// Bootstrap implements dut.DUT.
func (r *runsc) Bootstrap(ctx context.Context, infoCh chan<- testbench.DUTInfo) error {
	// runsc will flush the addresses so we collect the info before we start runsc.
	info, err := linux.DUTInfo()
	if err != nil {
		return fmt.Errorf("failed to collect information about the DUT: %w", err)
	}

	// Start and Wait for the posix_server.
	cmd := exec.CommandContext(
		ctx,
		r.runscPath,
		"-root", r.rootDir,
		"-network", "sandbox",
		"-debug",
		"-debug-log",
		r.runscLogsPath,
		"-log-format=text",
		"-TESTONLY-unsafe-nonroot=true",
		"-net-raw=true",
		fmt.Sprintf("-panic-signal=%d", unix.SIGTERM),
		"-watchdog-action=panic",
		"run",
		"-bundle", r.bundleDir,
		r.containerID,
	)
	done, err := dut.StartPosixServer(cmd)
	if err != nil {
		return nil
	}

	select {
	case <-done:
		// runsc will keep using the assigned ip and mac addresses, but the device
		// id could have changed, we need to figure it out.
		remoteDevID, err := r.remoteDevID()
		if err != nil {
			return fmt.Errorf("failed to get test dev id: %w", err)
		}
		info.Net.RemoteDevID = remoteDevID
		infoCh <- info
	case <-ctx.Done():
		return fmt.Errorf("bootstrap context cancelled before posix server is ready: %w", ctx.Err())
	}
	return cmd.Wait()
}

// Cleanup implements dut.DUT.
func (r *runsc) Cleanup() {
	r.cleanupRootDir()
	r.cleanupBundleDir()
}

// undeclaredOutput creates a path under the undeclared outputs directory.
func undeclaredOutput(name string) (string, error) {
	if dir, ok := os.LookupEnv("TEST_UNDECLARED_OUTPUTS_DIR"); ok {
		return filepath.Join(dir, name), nil
	}
	return "", fmt.Errorf("no TEST_UNDECLARED_OUTPUTS_DIR env var")
}

// remoteDevID gets the id of the test interface inside the runsc container.
func (r *runsc) remoteDevID() (uint32, error) {
	runscDevIDPath, err := testutil.FindFile("test/packetimpact/dut/runsc/devid")
	if err != nil {
		return 0, fmt.Errorf("failed to find binary runsc_devid: %w", err)
	}
	cmd := exec.Command(
		r.runscPath,
		"-root",
		r.rootDir,
		"-TESTONLY-unsafe-nonroot=true",
		"exec",
		r.containerID,
		runscDevIDPath,
		dut.TestIface,
	)
	bytes, err := cmd.CombinedOutput()
	output := string(bytes)
	if err != nil {
		return 0, fmt.Errorf("failed to get the remote device id: %w, output: %s", err, output)
	}
	id, err := strconv.Atoi(output)
	if err != nil {
		return 0, fmt.Errorf("%s is not a number: %w", output, err)
	}
	return uint32(id), nil
}
