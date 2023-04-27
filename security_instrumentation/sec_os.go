// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package security_instrumentation

import (
	"os"
	"os/exec"
	"reflect"
	"strings"

	logging "github.com/newrelic/csec-go-agent/internal/security_logs"
	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

//go:noinline
func secOpenFile_s(name string, flag int, perm os.FileMode) (*os.File, error) {
	if secIntercept.IsDisable() {
		return secOpenFile_s(name, flag, perm)
	}
	eventId := secIntercept.TraceFileOperation(name, flag, true)
	file, err := secOpenFile_s(name, flag, perm)
	secIntercept.SendExitEvent(eventId, err)
	return file, err
}

//go:noinline
func secOpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	if secIntercept.IsDisable() {
		return secOpenFile_s(name, flag, perm)
	}
	eventId := secIntercept.TraceFileOperation(name, flag, true)
	file, err := secOpenFile_s(name, flag, perm)
	secIntercept.SendExitEvent(eventId, err)
	return file, err
}

//go:noinline
func secRemove(name string) error {
	if secIntercept.IsDisable() {
		return secRemove_s(name)
	}
	eventId := secIntercept.TraceFileOperation(name, -1, false)
	err := secRemove_s(name)
	secIntercept.SendExitEvent(eventId, err)
	return err
}

//go:noinline
func secRemove_s(name string) error {
	if secIntercept.IsDisable() {
		return secRemove_s(name)
	}
	eventId := secIntercept.TraceFileOperation(name, -1, false)
	err := secRemove_s(name)
	secIntercept.SendExitEvent(eventId, err)
	return err
}

//go:noinline
func secStartProcess_s(name string, argv []string, attr *os.ProcAttr) (*os.Process, error) {
	if secIntercept.IsDisable() {
		return secStartProcess_s(name, argv, attr)
	}
	logger.Debugln("Hook Called : ", "os.StartProcess")
	eventID := secIntercept.TraceSystemCommand(strings.Join(argv, " "))
	out, err := secStartProcess_s(name, argv, attr)
	secIntercept.SendExitEvent(eventID, err)
	return out, err
}

//go:noinline
func secStartProcess(name string, argv []string, attr *os.ProcAttr) (*os.Process, error) {
	if secIntercept.IsDisable() {
		return secStartProcess_s(name, argv, attr)
	}
	logger.Debugln("Hook Called : ", "os.StartProcess")
	eventID := secIntercept.TraceSystemCommand(strings.Join(argv, " "))
	out, err := secStartProcess_s(name, argv, attr)
	secIntercept.SendExitEvent(eventID, err)
	return out, err
}

type SecCmd struct {
	exec.Cmd
}

//go:noinline
func (c *SecCmd) secStart() error {
	if secIntercept.IsDisable() {
		return c.secStart_s()
	}
	logger.Debugln("Hook Called : ", "(*exec.Cmd).Start")
	if c != nil {
		if err := reflect.ValueOf(c).Elem().FieldByName("Err"); err.IsValid() {
			if !err.IsNil() {
				secIntercept.TraceSystemCommand(strings.Join(c.Args, " "))
			}
		} else {
			err := reflect.ValueOf(c).Elem().FieldByName("lookPathErr")
			if err.IsValid() {
				if !err.IsNil() {
					secIntercept.TraceSystemCommand(strings.Join(c.Args, " "))
				}
			}
		}
	}
	return c.secStart_s()
}

//go:noinline
func (c *SecCmd) secStart_s() error {
	if secIntercept.IsDisable() {
		return c.secStart_s()
	}
	logger.Debugln("Hook Called : ", "(*exec.Cmd).Start")
	if c != nil {
		if err := reflect.ValueOf(c).Elem().FieldByName("Err"); err.IsValid() {
			if !err.IsNil() {
				secIntercept.TraceSystemCommand(strings.Join(c.Args, " "))
			}
		} else {
			err := reflect.ValueOf(c).Elem().FieldByName("lookPathErr")
			if err.IsValid() {
				if !err.IsNil() {
					secIntercept.TraceSystemCommand(strings.Join(c.Args, " "))
				}
			}
		}
	}
	return c.secStart_s()
}
func initFilehooks() {
	e := secIntercept.HookWrap(os.OpenFile, secOpenFile, secOpenFile_s)
	logging.IsHooked("os.OpenFile", e)
	e = secIntercept.HookWrap(os.Remove, secRemove, secRemove_s)
	logging.IsHooked("os.Remove", e)
}

func initOshooks() {
	e := secIntercept.HookWrap(os.StartProcess, secStartProcess, secStartProcess_s)
	logging.IsHooked("os.StartProcess", e)
	e = secIntercept.HookWrapInterface((*exec.Cmd).Start, (*SecCmd).secStart, (*SecCmd).secStart_s)
	logging.IsHooked("(*exec.Cmd).Start", e)
}
