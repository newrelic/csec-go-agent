//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0
package security_sysinfo

import (
	"errors"
)

func DiskFreeSpace(path string) uint64 {
	return 0
}

func GetLoadavg() (string, error) {
	return "0", errors.New("GetLoadavg not supported this Arch")
}
