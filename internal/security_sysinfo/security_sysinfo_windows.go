// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package security_sysinfo

import (
	"errors"
	"syscall"
	"unsafe"
)

type DiskUsage struct {
	freeBytes  int64
	totalBytes int64
	availBytes int64
}

// NewDiskUsages returns an object holding the disk usage of volumePath
// or nil in case of error (invalid path, etc)
func DiskFreeSpace(volumePath string) uint64 {

	h := syscall.MustLoadDLL("kernel32.dll")
	c := h.MustFindProc("GetDiskFreeSpaceExW")

	diskusage := &DiskUsage{}

	c.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(volumePath))),
		uintptr(unsafe.Pointer(&diskusage.freeBytes)),
		uintptr(unsafe.Pointer(&diskusage.totalBytes)),
		uintptr(unsafe.Pointer(&diskusage.availBytes)))

	return uint64(diskusage.freeBytes)
}

func GetLoadavg() (string, error) {
	return "0", errors.New("GetLoadavg not supported for windows")
}
