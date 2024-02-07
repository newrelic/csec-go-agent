//go:build !windows

// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0
package security_sysinfo

import (
	"errors"
	"os"
	"strings"
	"syscall"
)

func DiskFreeSpace(path string) uint64 {
	var stats syscall.Statfs_t
	err := syscall.Statfs(path, &stats)
	if err != nil {
		return stats.Bfree * uint64(stats.Bsize)
	}
	return stats.Bfree * uint64(stats.Bsize)
}

func GetLoadavg() (string, error) {
	file, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return "0", err
	}
	lavg := strings.Split(string(file), " ")
	if len(lavg) > 3 {
		return lavg[1], nil
	}
	return "0", errors.New("supported Loadavg not found in /proc/loadavg")
}
