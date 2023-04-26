// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package csec_robertkrimen_otto

import (
	"bytes"
	"io"

	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
	"github.com/robertkrimen/otto"
)

var logger = secIntercept.GetLogger("otto")

func src2string(s interface{}) string {
	//"github.com/robertkrimen/otto"o
	//src may be a string, a byte slice, a bytes.Buffer, or an io.Reader, but it MUST always be in UTF-8.
	logger.Debugln("in src2string - otto")
	//src may also be a Script.
	switch s.(type) {
	case nil:
		return ""
	case string:
		ss, ok := s.(string)
		if ok {
			return string(ss)
		}
	case []byte:
		b, ok := s.([]byte)
		if ok {
			return string(b)
		}
	case bytes.Buffer:
		bb, ok := s.(bytes.Buffer)
		if ok {
			return (&bb).String()
		}
	case io.Reader:
		ir, ok := s.(io.Reader)
		if ok {
			buff := make([]byte, 4096)
			_, err := ir.Read(buff)
			if err == nil {
				return string(buff)
			} else {
				logger.Errorln("otto: failed to read ioReader src", ir)
			}
		}
	}
	return ""
}

type SecOtto struct {
	otto.Otto
}

//go:noinline
func (k SecOtto) secRun_s(src interface{}) (otto.Value, error) {
	if secIntercept.IsDisable() {
		return k.secRun_s(src)
	}
	logger.Debugln("------------ otto.Run-hook", "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if src != nil {
		e := src2string(src)
		if e != "" {
			eventID = secIntercept.TraceJsOperation(e)
		}
	}
	value, err := k.secRun_s(src)
	secIntercept.SendExitEvent(eventID, err)
	return value, err
}

//go:noinline
func (k SecOtto) secRun(src interface{}) (otto.Value, error) {
	if secIntercept.IsDisable() {
		return k.secRun_s(src)
	}
	logger.Debugln("------------ otto.Run-hook", "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if src != nil {
		e := src2string(src)
		if e != "" {
			eventID = secIntercept.TraceJsOperation(e)
		}
	}
	value, err := k.secRun_s(src)
	secIntercept.SendExitEvent(eventID, err)
	return value, err
}

//go:noinline
func (k SecOtto) secEval_s(src interface{}) (otto.Value, error) {
	if secIntercept.IsDisable() {
		return k.secEval_s(src)
	}
	logger.Debugln("------------ otto.Eval-hook", "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if src != nil {
		e := src2string(src)
		if e != "" {
			eventID = secIntercept.TraceJsOperation(e)
		}
	}
	value, err := k.secEval_s(src)
	secIntercept.SendExitEvent(eventID, err)
	return value, err
}

//go:noinline
func (k SecOtto) secEval(src interface{}) (otto.Value, error) {
	if secIntercept.IsDisable() {
		return k.secEval_s(src)
	}
	logger.Debugln("------------ otto.Eval-hook", "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if src != nil {
		e := src2string(src)
		if e != "" {
			eventID = secIntercept.TraceJsOperation(e)
		}
	}
	value, err := k.secEval_s(src)
	secIntercept.SendExitEvent(eventID, err)
	return value, err
}

func init() {
	if !secIntercept.IsAgentInitializedForHook() || secIntercept.IsForceDisable() || !secIntercept.IsHookingoIsSupported() {
		return
	}

	e := secIntercept.HookWrapInterface((otto.Otto).Run, (SecOtto).secRun, (SecOtto).secRun_s)
	secIntercept.IsHookedLog("(otto.Otto).Run", e)
	e = secIntercept.HookWrapInterface((otto.Otto).Eval, (SecOtto).secEval, (SecOtto).secEval_s)
	secIntercept.IsHookedLog("(otto.Otto).Eval", e)
}
