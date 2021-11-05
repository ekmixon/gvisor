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

// Test runner for packetimpact tests.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	netdevs "gvisor.dev/gvisor/test/packetimpact/netdevs/netlink"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

var (
	dutBinary     = ""
	testBinary    = ""
	expectFailure = false
	numDUTs       = 1
	variant       = ""
)

func main() {
	if os.Args[0] == "/proc/self/exe" {
		// CI environment passes args that is used by the docker runner but not us,
		// ContinueOnError so that we don't report unknown command line arguments.
		fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
		fs.StringVar(&dutBinary, "dut_binary", dutBinary, "path to the DUT binary")
		fs.StringVar(&testBinary, "testbench_binary", testBinary, "path to the test binary")
		fs.BoolVar(&expectFailure, "expect_failure", expectFailure, "whether the test is expected to fail")
		fs.IntVar(&numDUTs, "num_duts", numDUTs, "number of DUTs to create")
		fs.StringVar(&variant, "variant", variant, "test variant could be native, gvisor or fuchsia")
		fs.Parse(os.Args[1:])

		g, ctx := errgroup.WithContext(context.Background())

		// Create all the DUTs.
		infoCh := make(chan testbench.DUTInfo, numDUTs)
		for i := 0; i < numDUTs; i++ {
			i := i
			g.Go(func() error {
				d, err := newDUT(i)
				if err != nil {
					return err
				}
				return d.bootstrap(ctx, infoCh)
			})
		}

		// Wait for all the DUTs to bootstrap.
		var infos []testbench.DUTInfo
		for i := 0; i < numDUTs; i++ {
			select {
			case <-ctx.Done():
				log.Fatalf("failed to bootstrap dut: %s", g.Wait())
			case info := <-infoCh:
				infos = append(infos, info)
			}
		}

		dutJSON, err := json.Marshal(&infos)
		if err != nil {
			log.Fatalf("failed to marshal json: %s", err)
		}

		for i := 0; i < numDUTs; i++ {
			ifaceName := tbSide.ifaceName(testLink, i)
			// When the Linux kernel receives a SYN-ACK for a SYN it didn't send, it
			// will respond with an RST. In most packetimpact tests, the SYN is sent
			// by the raw socket, the kernel knows nothing about the connection, this
			// behavior will break lots of TCP related packetimpact tests. To prevent
			// this, we can install the following iptables rules. The raw socket that
			// packetimpact tests use will still be able to see everything.
			for _, iptables := range []string{"/sbin/iptables-nft", "/sbin/ip6tables-nft"} {
				cmd := exec.Command(iptables, "-A", "INPUT", "-i", ifaceName, "--proto", "tcp", "-j", "DROP")
				if output, err := cmd.CombinedOutput(); err != nil {
					log.Fatalf("failed to set iptables: %s, output: %s", err, string(output))
				}
			}
			// Start packet capture.
			g.Go(func() error {
				return writePcap(ctx, ifaceName)
			})
		}

		// Start the test itself.
		testResult := make(chan error, 1)
		go func() {
			testArgs := []string{"--dut_infos_json", string(dutJSON)}
			if variant == "native" {
				testArgs = append(testArgs, "-native")
			}
			test := exec.Command(testBinary, testArgs...)
			test.SysProcAttr = &syscall.SysProcAttr{
				Pdeathsig: syscall.SIGTERM,
			}
			test.Stderr = os.Stderr
			test.Stdout = os.Stdout
			testResult <- test.Run()
		}()

		select {
		case <-ctx.Done():
			log.Fatalf("background tasks exited early: %s", g.Wait())
		case err := <-testResult:
			var exitStatus *exec.ExitError
			switch {
			case err != nil && !errors.As(err, &exitStatus):
				log.Fatalf("unknown error when executing test: %s", err)
			case err != nil && !expectFailure:
				os.Exit(err.(*exec.ExitError).ExitCode())
			case err == nil && expectFailure:
				log.Fatalf("the test is expected to fail")
			}
		}
	} else {
		// We are run for the first time, create a new user name space and a new
		// network namespace.
		cmd := exec.Command("/proc/self/exe", os.Args[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
			Pdeathsig:  syscall.SIGTERM,
			UidMappings: []syscall.SysProcIDMap{
				{
					ContainerID: 0,
					HostID:      os.Getuid(),
					Size:        1,
				},
			},
			GidMappings: []syscall.SysProcIDMap{
				{
					ContainerID: 0,
					HostID:      os.Getgid(),
					Size:        1,
				},
			},
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = os.Environ()
		if err := cmd.Run(); err != nil {
			if exitStatus, ok := err.(*exec.ExitError); ok {
				os.Exit(exitStatus.ExitCode())
			} else {
				log.Fatalf("unknown failure: %s", err)
			}
		}
	}
}

type dut struct {
	cmd       *exec.Cmd
	id        int
	completeR *os.File
}

func newDUT(id int) (*dut, error) {
	cmd := exec.Command(dutBinary, "--ctrl_iface", dutSide.ifaceName(ctrlLink, id), "--test_iface", dutSide.ifaceName(testLink, id))

	// Create the pipe for completion signal
	completeR, completeW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe for completion signal: %w", err)
	}

	// Create a new network namespace for the DUT.
	dutNetNS, err := newNetNS()
	if err != nil {
		return nil, fmt.Errorf("failed to create a new namespace for DUT: %w", err)
	}

	// Pass these two file descriptors to the DUT.
	cmd.ExtraFiles = append(cmd.ExtraFiles, completeW, os.NewFile(uintptr(dutNetNS), "dutNS"))

	// Deliver SIGTERM to the child when the runner exits.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}

	// Use the same environment in the DUT binary.
	cmd.Env = os.Environ()

	// Stream outputs from the DUT binary.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Now create the veth pairs to connect the DUT and us.
	for _, typ := range []linkType{ctrlLink, testLink} {
		dutVeth := netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name: dutSide.ifaceName(typ, id),
			},
			PeerName: tbSide.ifaceName(typ, id),
		}
		tbVeth := netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name: tbSide.ifaceName(typ, id),
			},
			PeerName: dutSide.ifaceName(typ, id),
		}
		if err := netlink.LinkAdd(&dutVeth); err != nil {
			return nil, fmt.Errorf("failed to add a %s veth pair for dut-%d: %w", typ, id, err)
		}

		tbIPv4 := typ.ipv4(uint8(id), 1)
		dutIPv4 := typ.ipv4(uint8(id), 2)

		// Move the DUT end into the created namespace.
		if err := netlink.LinkSetNsFd(&dutVeth, int(dutNetNS)); err != nil {
			return nil, fmt.Errorf("failed to move %s veth end to dut-%d: %w", typ, id, err)
		}

		for _, conf := range []struct {
			ns   netNS
			addr *netlink.Addr
			veth *netlink.Veth
		}{
			{ns: currentNetNS, addr: tbIPv4, veth: &tbVeth},
			{ns: dutNetNS, addr: dutIPv4, veth: &dutVeth},
		} {
			if err := conf.ns.Do(func() error {
				// Disable the DAD so that the generated IPv6 address can be used immediately.
				if err := disableDad(conf.veth.Name); err != nil {
					return fmt.Errorf("failed to disable DAD on %s: %w", conf.veth.Name, err)
				}
				// Manually add the IPv4 address.
				if err := netlink.AddrAdd(conf.veth, conf.addr); err != nil {
					return fmt.Errorf("failed to add addr %s to %s: %w", conf.addr, conf.veth.Name, err)
				}
				// Bring the link up.
				if err := netlink.LinkSetUp(conf.veth); err != nil {
					return fmt.Errorf("failed to set %s up: %w", conf.veth.Name, err)
				}
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	// Bring the loopback interface up in both namespaces.
	for _, ns := range []netNS{currentNetNS, dutNetNS} {
		if err := ns.Do(func() error {
			return netlink.LinkSetUp(&netlink.Device{
				LinkAttrs: netlink.LinkAttrs{
					Name: "lo",
				},
			})
		}); err != nil {
			return nil, fmt.Errorf("failed to bring loopback up: %w", err)
		}
	}

	return &dut{cmd: cmd, id: id, completeR: completeR}, nil
}

func (d *dut) bootstrap(ctx context.Context, infoCh chan<- testbench.DUTInfo) error {
	if err := d.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start DUT %d: %w", d.id, err)
	}
	for _, file := range d.cmd.ExtraFiles {
		if err := file.Close(); err != nil {
			return fmt.Errorf("close(%d) = %w", file.Fd(), err)
		}
	}

	g, _ := errgroup.WithContext(ctx)
	g.Go(func() error {
		return d.cmd.Wait()
	})
	g.Go(func() error {
		bytes, err := io.ReadAll(d.completeR)
		if err != nil {
			return fmt.Errorf("failed to read from %s complete pipe: %w", d.name(), err)
		}
		var dutInfo testbench.DUTInfo
		if err := json.Unmarshal(bytes, &dutInfo); err != nil {
			return fmt.Errorf("invalid response from %s: %s, received: %s", d.name(), err, string(bytes))
		}
		testIface, testIPv4, testIPv6, err := netdevs.IfaceInfo(tbSide.ifaceName(testLink, d.id))
		if err != nil {
			return fmt.Errorf("failed to gather information about the testbench: %w", err)
		}
		dutInfo.Net.LocalMAC = testIface.Attrs().HardwareAddr
		dutInfo.Net.LocalIPv4 = testIPv4.IP.To4()
		dutInfo.Net.LocalIPv6 = testIPv6.IP
		dutInfo.Net.LocalDevID = uint32(testIface.Attrs().Index)
		dutInfo.Net.LocalDevName = testIface.Attrs().Name
		infoCh <- dutInfo
		return nil
	})

	return g.Wait()
}

func (d *dut) name() string {
	return fmt.Sprintf("dut-%d", d.id)
}

// writePcap creates the packet capture while the test is running.
func writePcap(ctx context.Context, iface string) error {
	testName := filepath.Base(testBinary)
	var pcap *os.File
	// Create the pcap file.
	if dir, ok := os.LookupEnv("TEST_UNDECLARED_OUTPUTS_DIR"); ok {
		fileName := fmt.Sprintf("%s_%s_%s.pcap", testName, time.Now().Format(time.RFC3339Nano), iface)
		path := filepath.Join(dir, fileName)
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("os.Create(%s): %s", path, err)
		}
		pcap = f
	} else {
		name := fmt.Sprintf("%s_%s_*.pcap", testName, iface)
		f, err := os.CreateTemp("", name)
		if err != nil {
			return fmt.Errorf("os.CreateTemp(%s): %s", name, err)
		}
		log.Printf("no TEST_UNDECLARED_OUTPUTS_DIR, packet capture will be written to: %s", f.Name())
		pcap = f
	}
	defer pcap.Close()

	// Start the packet capture.
	pcapw := pcapgo.NewWriter(pcap)
	if err := pcapw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		return fmt.Errorf("WriteFileHeader: %w", err)
	}
	handle, err := pcapgo.NewEthernetHandle(iface)
	if err != nil {
		return fmt.Errorf("pcapgo.NewEthernetHandle(%s): %w", iface, err)
	}
	source := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	for {
		select {
		case packet := <-source.Packets():
			if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				return fmt.Errorf("pcapw.WritePacket(): %w", err)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// disableDad disables DAD on the iface when assigning IPv6 addrs.
func disableDad(iface string) error {
	// DAD operation and mode on a given interface will be selected according to
	// the maximum value of conf/{all,interface}/accept_dad. So we set it to 0 on
	// both `iface` and `all`.
	for _, name := range []string{iface, "all"} {
		path := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", name)
		if err := os.WriteFile(path, []byte("0"), 0); err != nil {
			return err
		}
	}
	return nil
}

// netNS is a network namespace.
type netNS int

const (
	currentNetNS netNS = -1
)

// newNetNS creates a new network namespace.
func newNetNS() (_ netNS, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Save the current namespace.
	nsPath := fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid())
	saved, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return currentNetNS, err
	}
	defer func() {
		err = unix.Close(saved)
	}()
	// Create the namespace via unshare(2).
	if err = unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return currentNetNS, err
	}
	// Switch back to the saved namespace and return the created namespace.
	defer func() {
		err = unix.Setns(saved, unix.CLONE_NEWNET)
	}()
	fd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return currentNetNS, err
	}
	return netNS(fd), nil
}

// Do calls the function in the given network namespace.
func (ns netNS) Do(f func() error) (err error) {
	if ns == currentNetNS {
		// Simply call the function if we are already in the namespace.
		return f()
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Create a fd to the current namespace.
	nsPath := fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid())
	saved, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() {
		err = unix.Close(saved)
	}()
	// Switch to the target namespace.
	if err := unix.Setns(int(ns), unix.CLONE_NEWNET); err != nil {
		return err
	}
	// Switch back when we are done.
	defer func() {
		err = unix.Setns(saved, unix.CLONE_NEWNET)
	}()
	return f()
}

// linkType describes if the link is for ctrl or test.
type linkType string

const (
	testLink linkType = "test"
	ctrlLink linkType = "ctrl"
)

// ipv4 creates an IPv4 address for the given network and host number.
func (l linkType) ipv4(network uint8, host uint8) *netlink.Addr {
	const (
		testNetworkNumber uint8 = 172
		ctrlNetworkNumber uint8 = 192
	)
	var leadingByte uint8
	switch l {
	case testLink:
		leadingByte = testNetworkNumber
	case ctrlLink:
		leadingByte = ctrlNetworkNumber
	default:
		panic(fmt.Sprintf("unknown link type: %s", l))
	}
	addr, err := netlink.ParseAddr(fmt.Sprintf("%d.0.%d.%d/24", leadingByte, network, host))
	if err != nil {
		panic(fmt.Sprintf("failed to parse ip net: %s", err))
	}
	return addr
}

// side describes which side of the link (tb/dut).
type side string

const (
	dutSide side = "dut"
	tbSide  side = "tb"
)

func (s side) ifaceName(typ linkType, id int) string {
	return fmt.Sprintf("%s-%d-%s", s, id, typ)
}
