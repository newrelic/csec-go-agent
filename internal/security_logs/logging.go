// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package security_logs

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()
var initlog = logrus.New()
var disable = false
var isInitilized = false

func Init(logFileName, initlogFileName, logFilepath string, pid int) {
	isInitilized = true
	if log == nil {
		log = logrus.New()
	}
	syscall.Umask(0)
	err := os.MkdirAll(logFilepath, os.ModePerm)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = os.Chmod(logFilepath, 0777)
	if err != nil {
		fmt.Println(err)
		return
	}
	//todo add exception handlin

	formatter := logrus.TextFormatter{
		ForceColors:     true,
		ForceQuote:      true,
		FullTimestamp:   true,
		TimestampFormat: "02-Jan-2006 15:04:05 MST",
		DisableSorting:  false,
		PadLevelText:    true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			filename := path.Base(f.File)
			return "", fmt.Sprintf("%d:%s:%d", pid, filename, f.Line)
		},
	}
	log.SetFormatter(&formatter)
	log.SetReportCaller(true)

	rotateFileHook, writer, err := NewRotateFileHook(RotateFileConfig{
		Filename:        filepath.Join(logFilepath, logFileName),
		MaxSize:         50, // megabytes
		MaxBackups:      2,
		Level:           logrus.TraceLevel,
		BaseLogFilename: logFileName,
	})

	if err != nil {
		fmt.Println(err)
		return
	}

	log.SetOutput(writer)
	initlog.SetLevel(logrus.InfoLevel)
	log.AddHook(rotateFileHook)
	init_initLog(initlogFileName, logFilepath, pid)
}

func init_initLog(initlogFileName, logFilepath string, pid int) {
	if initlog == nil {
		initlog = logrus.New()
	}

	formatter := logrus.TextFormatter{
		ForceColors:    true,
		ForceQuote:     false,
		FullTimestamp:  false,
		DisableSorting: false,
		PadLevelText:   false,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			return "", " "
		},
	}
	initlog.SetFormatter(&formatter)
	initlog.SetReportCaller(true)

	rotateFileHook, writer, err := NewRotateFileHook(RotateFileConfig{
		Filename:        filepath.Join(logFilepath, initlogFileName),
		MaxSize:         50, // megabytes
		MaxBackups:      2,
		Level:           logrus.TraceLevel,
		BaseLogFilename: initlogFileName,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	initlog.SetOutput(writer)
	initlog.SetLevel(logrus.InfoLevel)
	initlog.AddHook(rotateFileHook)
	printInitLog()

}

func SetLogLevel(level string) {
	if os.Getenv("NR_CSEC_DEBUG_MODE") == "true" {
		log.SetLevel(logrus.DebugLevel)
		return
	}
	switch strings.ToUpper(level) {
	case "TRACE":
		log.SetLevel(logrus.TraceLevel)
	case "DEBUG":
		log.SetLevel(logrus.DebugLevel)
	case "INFO":
		log.SetLevel(logrus.InfoLevel)
	case "WARN":
		log.SetLevel(logrus.WarnLevel)
	case "ERROR":
		log.SetLevel(logrus.ErrorLevel)
	case "FATAL":
		log.SetLevel(logrus.FatalLevel)
	case "PANIC":
		log.SetLevel(logrus.PanicLevel)
	default:
		log.SetLevel(logrus.InfoLevel)
	}
}

func GetLogger(loggerName string) *logrus.Entry {
	return log.WithFields(logrus.Fields{"logger": loggerName})
}

func InitLogger() *logrus.Logger {
	if initlog == nil {
		initlog = logrus.New()
	}
	return initlog
}

func NewStage(stageId, code, stage string) {
	if disable {
		return
	}
	logger1 := InitLogger()
	print := fmt.Sprintf("[STEP-%s][BEGIN][%s] %s", stageId, code, stage)
	logger1.Infoln(print)
}

func EndStage(stageId, code string) {
	if disable {
		return
	}
	logger1 := InitLogger()
	print := fmt.Sprintf("[STEP-%s][%s][COMPLETE]", stageId, code)
	logger1.Infoln(print)
}
func PrintInitlog(logs interface{}, stagecode string) {
	if disable {
		return
	}
	if initlog == nil {
		initlog = logrus.New()
	}
	print := fmt.Sprintf("[%s]: %s", stagecode, logs)
	initlog.Infoln(print)
}

func PrintInitErrolog(logs string, stagecode string) {
	if disable {
		return
	}
	if initlog == nil {
		initlog = logrus.New()
	}
	print := fmt.Sprintf("[%s]: %s", stagecode, logs)
	initlog.Errorln(print)
}
func PrintWarnlog(logs string, stagecode string) {
	if disable {
		return
	}
	if initlog == nil {
		initlog = logrus.New()
	}
	print := fmt.Sprintf("[%s]: %s", stagecode, logs)
	initlog.Warnln(print)
}

func Disableinitlogs() {
	disable = true
}
