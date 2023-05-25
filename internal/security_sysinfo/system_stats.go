// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_sysinfo

import (
	"fmt"
	"runtime"
	"strconv"
)

func GetStats(pid, applicationPath string) map[string]interface{} {
	stats := map[string]interface{}{}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	stats["processMaxHeapMB"] = byteToMb(float64(m.HeapSys))     // byte to mb
	stats["processHeapUsageMB"] = byteToMb(float64(m.HeapAlloc)) // byte to mb   allocBytes:   cur.memStats.Alloc,
	stats["processRssMB"] = byteToMb(float64(m.Sys))             // byte to mb
	stats["nCores"] = runtime.NumCPU()
	stats["rootDiskFreeSpaceMB"] = byteToMb(float64(DiskFreeSpace("/")))                   // byte to mb
	stats["processDirDiskFreeSpaceMB"] = byteToMb(float64(DiskFreeSpace(applicationPath))) // byte to mb
	systemFreeMemoryMB, _ := FreePhysicalMemoryBytes()
	stats["systemFreeMemoryMB"] = byteToMb(float64(systemFreeMemoryMB)) // byte to mb
	systemTotalMemoryMB, _ := PhysicalMemoryBytes()
	stats["systemTotalMemoryMB"] = byteToMb(float64(systemTotalMemoryMB)) // byte to mb

	avg, err := GetLoadavg() //don't have support for windows
	if err == nil {
		stats["systemCpuLoad"] = avg
	}
	return stats
}

func byteToMb(data float64) float64 {

	data = data / (1024 * 1024)
	return toFixed(data)
}

func toFixed(data float64) float64 {
	getSize := fmt.Sprintf("%.2f", data)
	if s, err := strconv.ParseFloat(getSize, 64); err == nil {
		return s
	}
	return data
}
