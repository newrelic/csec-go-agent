// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package security_sysinfo

import (
	"syscall"
	"unsafe"
)

// PhysicalMemoryBytes returns the total amount of host memory.
func PhysicalMemoryBytes() (uint64, error) {
	// https://msdn.microsoft.com/en-us/library/windows/desktop/cc300158(v=vs.85).aspx
	// http://stackoverflow.com/questions/30743070/query-total-physical-memory-in-windows-with-golang
	mod := syscall.NewLazyDLL("kernel32.dll")
	proc := mod.NewProc("GetPhysicallyInstalledSystemMemory")
	var memkb uint64

	ret, _, err := proc.Call(uintptr(unsafe.Pointer(&memkb)))
	// return value TRUE(1) succeeds, FAILED(0) fails
	if ret != 1 {
		return 0, err
	}

	return memkb * 1024, nil
}

func FreePhysicalMemoryBytes() (uint64, error) {
	mod, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return 0, err
	}

	proc, err := mod.FindProc("GlobalMemoryStatusEx")
	if err != nil {
		return 0, err
	}
	var memkb uint64
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(&memkb)))
	if r == 0 {
		return 0, err
	}

	return memkb * 1024, nil
}
