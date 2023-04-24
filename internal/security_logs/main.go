// Copyright 2022 New Relic Corporation. All rights reserved.

package security_logs

import (
	"fmt"
	"sync"
)

// TODO update this file for centralized Logs
var logger = GetLogger("hookingLog")
var initlogs = InitLogger()
var traceHook = sync.Map{}

func IsHooked(name string, e error) {
	if !isInitilized {
		traceHook.Store(name, e)
		return
	}
	if e != nil {
		print := fmt.Sprintf("[%s]: %s", "INSTRUMENTATION", "Not able to hook function")
		logger.WithField("functionName", name).WithField("error", e.Error()).Errorln("Not able to hook function")
		initlogs.WithField("functionName", name).WithField("error", e.Error()).Errorln(print)
	} else {
		print := fmt.Sprintf("[%s]: %s", "INSTRUMENTATION", "Function successfully hooked")
		logger.WithField("functionName", name).Infoln("Function successfully hooked")
		initlogs.WithField("functionName", name).Infoln(print)
	}
}
func Info(name ...string) {

}
func Debug(name ...string) {

}
func Error(name string, e error) {

}

func printInitLog() {
	isInitilized = true
	NewStage("1", "INSTRUMENTATION", "Applying instrumentation")
	traceHook.Range(func(k, v interface{}) bool {
		if v == nil {
			IsHooked(k.(string), nil)
		} else {
			IsHooked(k.(string), v.(error))
		}
		return true
	})
	traceHook = sync.Map{}
}

var errorBuffer = [5]string{}
var maxSize = 5
var errorcounter = 0
var hmutex sync.Mutex

func trackError(err string) {
	hmutex.Lock()
	defer hmutex.Unlock()
	if errorcounter == maxSize {
		errorcounter = 0
	}
	errorBuffer[errorcounter] = err
	errorcounter++
}
func GetErrorLogs() interface{} {
	return errorBuffer
}
