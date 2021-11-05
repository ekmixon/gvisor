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

// A helper binary to get the device ID in the runsc container.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/vishvananda/netlink"
)

func main() {
	link, err := netlink.LinkByName(os.Args[1])
	if err != nil {
		log.Fatalf("could not find the link: %s", err)
	}
	fmt.Printf("%d", link.Attrs().Index)
}
