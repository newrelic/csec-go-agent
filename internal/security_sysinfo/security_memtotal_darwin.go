// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package security_sysinfo

import (
	"syscall"
	"unsafe"
	"regexp"
	"os/exec"
	"strconv"
	"errors"
)

var rePageSize = regexp.MustCompile("page size of ([0-9]*) bytes")
var reFreePages = regexp.MustCompile("Pages free: *([0-9]*)\\.")

// PhysicalMemoryBytes returns the total amount of host memory.
func PhysicalMemoryBytes() (uint64, error) {
	mib := []int32{6 /* CTL_HW */, 24 /* HW_MEMSIZE */}

	buf := make([]byte, 8)
	bufLen := uintptr(8)

	_, _, e1 := syscall.Syscall6(syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bufLen)),
		uintptr(0), uintptr(0))

	if e1 != 0 {
		return 0, e1
	}

	if bufLen != 8 {
		return 0, syscall.EIO
	}

	return *(*uint64)(unsafe.Pointer(&buf[0])), nil
}

func FreePhysicalMemoryBytes() (uint64, error) {
	cmd := exec.Command("vm_stat")
	outBytes, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	pageSize, err := parseProcMeminfo(outBytes, reFreePages)
	numberOfPage, err1 := parseProcMeminfo(outBytes, reFreePages)
	if err == nil && err1 == nil {
		return pageSize * numberOfPage * 1024, nil
	}
	return 0, err
}

func parseProcMeminfo(f []byte, r *regexp.Regexp) (uint64, error) {
	if m := r.FindSubmatch(f); m != nil {
		kb, err := strconv.ParseUint(string(m[1]), 10, 64)
		if err != nil {
			return 0, err
		}
		return kb, nil
	}

	return 0, errors.New("supported MemTotal not found in /proc/meminfo")
}
