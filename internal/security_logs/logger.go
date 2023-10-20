// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package security_logs

import (
	"fmt"
	"io"
	"log"
)

type logFile struct {
	logger         *log.Logger
	isDebugMode    bool
	mode           string
	isActive       bool
	cache          []interface{}
	iscache        bool
	rotateFileHook *RotateFileHook
	isDefault      bool
}

type Logger interface {
	Errorln(...interface{})
	Warnln(...interface{})
	Infoln(...interface{})
	Debugln(...interface{})
}

// New creates a basic Logger.
func UpdateLogger(w io.Writer, mode string, pid int, logF *logFile, rotateFileHook *RotateFileHook, isDefault bool) {
	logF.logger = log.New(w, fmt.Sprintf("%d", pid), log.Ldate|log.Ltime|log.Lmsgprefix|log.LstdFlags|log.LUTC|log.Lshortfile)
	logF.isActive = true
	logF.iscache = false
	logF.rotateFileHook = rotateFileHook
	logF.isDefault = isDefault
	logF.setLevel(mode)
	logF.cleanCache()
	return
}

func DefaultLogger(iscache1 bool) *logFile {
	logF := &logFile{isActive: false, iscache: iscache1, isDefault: true}
	return logF
}

func (f *logFile) fire(level string, msg ...interface{}) {
	logm := fmt.Sprintln(msg...)

	if level == "ERROR" {
		errLevel := fmt.Sprintf("\x1b[%dm%s\x1b[0m", 31, "ERROR")
		logm = fmt.Sprintf(" [%s] %s", errLevel, logm)
	} else {
		logm = fmt.Sprintf(" [%s] %s", level, logm)
	}

	if f.iscache && f.logger == nil {
		f.cache = append(f.cache, logm)
	}

	if !f.isActive || f.logger == nil {
		return
	}

	if f.rotateFileHook != nil {
		logm = f.rotateFileHook.Fire(logm, level, f.isDefault)
	}

	f.logger.Output(3, logm)
}

func (f *logFile) Errorln(msg ...interface{}) {
	f.fire("ERROR", msg...)
}
func (f *logFile) Warnln(msg ...interface{}) {
	f.fire("WARN", msg...)
}
func (f *logFile) Infoln(msg ...interface{}) {
	f.fire("INFO", msg...)
}
func (f *logFile) Info(msg ...interface{}) {
	f.fire("INFO", msg...)
}
func (f *logFile) Debugln(msg ...interface{}) {
	if f.isDebugMode {
		f.fire("DEBUG", msg...)
	}
}
func (f *logFile) DebugEnabled() bool { return f.isDebugMode }

func (f *logFile) setLevel(mode string) {
	if f.isDefault {
		f.isDebugMode = false
	} else if mode == "DEBUG" {
		f.isDebugMode = true
	}
	f.mode = mode
}

func (f *logFile) cleanCache() {
	for i := range f.cache {
		f.logger.Output(3, fmt.Sprintf("%s", f.cache[i]))
	}
	f.cache = make([]interface{}, 0)
}

func (f *logFile) IsDebug() bool{
	return f.isDebugMode
}