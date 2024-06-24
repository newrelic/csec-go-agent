//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package security_sysinfo

import "errors"

// PhysicalMemoryBytes returns the total amount of host memory.
func PhysicalMemoryBytes() (uint64, error) {
	return 0, errors.New("PhysicalMemoryBytes not supported this Arch")
}

func FreePhysicalMemoryBytes() (uint64, error) {
	return 0, errors.New("FreePhysicalMemoryBytes not supported this Arch")
}
