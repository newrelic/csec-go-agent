// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package security_logs

import (
	"fmt"
	"path/filepath"
)

var initLogger = DefaultLogger(true)

func init_initLogger(initlogFileName, logFilepath string, pid int) {

	rotateFileHook, writer, isDefault, _ := NewRotateFileHook(RotateFileConfig{
		Filename:        filepath.Join(logFilepath, initlogFileName),
		Filepath:        logFilepath,
		MaxSize:         50, // megabytes
		MaxBackups:      2,
		BaseLogFilename: initlogFileName,
	})

	UpdateLogger(writer, "INFO", pid, initLogger, rotateFileHook, isDefault)
}

func InitLogger() *logFile {
	return initLogger
}

func EndStage(stageId, logs interface{}) {
	print := fmt.Sprintf("[STEP-%s] => %s", stageId, logs)
	PrintInitlog(print)
}
func PrintInitlog(logs interface{}) {
	initLogger.Infoln(logs)
	agentLogger.Infoln(logs)
}

func PrintInitErrolog(logs string) {
	initLogger.Errorln(logs)
	agentLogger.Errorln(logs)
}
func PrintWarnlog(logs string) {
	initLogger.Warnln(logs)
	agentLogger.Warnln(logs)
}
func Disableinitlogs() {
	initLogger.isActive = false
}
