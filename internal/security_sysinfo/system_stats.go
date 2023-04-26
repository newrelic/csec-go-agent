// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package security_sysinfo

import (
	"fmt"
	"runtime"
	"strconv"
	"syscall"

	"github.com/mackerelio/go-osstat/loadavg"
	"github.com/pbnjay/memory"
	"github.com/struCoder/pidusage"
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
	stats["systemFreeMemoryMB"] = byteToMb(float64(memory.FreeMemory()))                   // byte to mb no impl in NR code
	stats["systemTotalMemoryMB"] = byteToMb(float64(memory.TotalMemory()))                 // byte to mb  // can be get from NR code
	avg, err := loadavg.Get()                                                              //don't have support for windows
	if err == nil {
		stats["systemCpuLoad"] = avg.Loadavg5
	}
	sysinfo, err := pidusage.GetStat(syscall.Getpid())
	if err == nil {
		stats["processCpuUsage"] = toFixed(sysinfo.CPU)
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
