load("//tools:defs.bzl", "go_library")

package(
    default_visibility = ["//test/packetimpact/dut:__subpackages__"],
    licenses = ["notice"],
)

go_library(
    name = "linux",
    testonly = 1,
    srcs = ["linux.go"],
    deps = [
        "//test/packetimpact/dut",
        "//test/packetimpact/netdevs/netlink",
        "//test/packetimpact/testbench",
    ],
)
