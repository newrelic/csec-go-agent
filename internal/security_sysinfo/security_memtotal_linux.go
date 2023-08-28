// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package security_sysinfo

import (
	"bufio"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
)

var (
	meminfoRe           = regexp.MustCompile(`^MemTotal:\s+([0-9]+)\s+[kK]B$`)
	memFreeinfoRe       = regexp.MustCompile(`^MemFree:\s+([0-9]+)\s+[kK]B$`)
	errMemTotalNotFound = errors.New("supported MemTotal not found in /proc/meminfo")
)

// PhysicalMemoryBytes returns the total amount of host memory.
func PhysicalMemoryBytes() (uint64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	return parseProcMeminfo(f, meminfoRe)
}

// PhysicalMemoryBytes returns the total amount of host memory.
func FreePhysicalMemoryBytes() (uint64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	return parseProcMeminfo(f, memFreeinfoRe)
}

func parseProcMeminfo(f io.Reader, r *regexp.Regexp) (uint64, error) {
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if m := r.FindSubmatch(scanner.Bytes()); m != nil {
			kb, err := strconv.ParseUint(string(m[1]), 10, 64)
			if err != nil {
				return 0, err
			}
			return kb * 1024, nil
		}
	}

	err := scanner.Err()
	if err == nil {
		err = errMemTotalNotFound
	}
	return 0, err
}
