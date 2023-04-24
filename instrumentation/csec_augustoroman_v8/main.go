// Copyright 2022 New Relic Corporation. All rights reserved.

package csec_augustoroman_v8

import (
	v8 "github.com/augustoroman/v8"
	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

var logger = secIntercept.GetLogger("csec_augustoroman_v8")

type SecContext struct {
	v8.Context
}

//go:noinline
func (k *SecContext) secEval_s(j, f string) (*v8.Value, error) {
	if secIntercept.IsDisable() {
		return k.secEval_s(j, f)
	}
	logger.Debugln("------------ v8Eval-hook", "in hook")
	eventID := secIntercept.TraceJsOperation(j)
	value, err := k.secEval_s(j, f)
	secIntercept.SendExitEvent(eventID, err)
	return value, err
}

//go:noinline
func (k *SecContext) secEval(j, f string) (*v8.Value, error) {
	if secIntercept.IsDisable() {
		return k.secEval_s(j, f)
	}
	logger.Debugln("------------ v8Eval-hook", "in hook")
	eventID := secIntercept.TraceJsOperation(j)
	value, err := k.secEval_s(j, f)
	secIntercept.SendExitEvent(eventID, err)
	return value, err
}

func init() {
	if !secIntercept.IsAgentInitializedForHook() || secIntercept.IsForceDisable() || !secIntercept.IsHookingoIsSupported() {
		return
	}

	e := secIntercept.HookWrapInterface((*v8.Context).Eval, (*SecContext).secEval, (*SecContext).secEval_s)
	secIntercept.IsHookedLog("(*v8.Context).Eval", e)
}
