//go:build !windows

// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package security_sysinfo

import "syscall"

func DiskFreeSpace(path string) uint64 {
	var stats syscall.Statfs_t
	err := syscall.Statfs(path, &stats)
	if err != nil {
		return stats.Bfree * uint64(stats.Bsize)
	}
	return stats.Bfree * uint64(stats.Bsize)
}
