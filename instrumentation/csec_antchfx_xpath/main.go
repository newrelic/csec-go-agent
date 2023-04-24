// Copyright 2022 New Relic Corporation. All rights reserved.

package csec_antchfx_xpath

import (
	"github.com/antchfx/xpath"
	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

var logger = secIntercept.GetLogger("csec_antchfx_xpath")

type SecxpathExpr struct {
	xpath.Expr
}

//go:noinline
func (e *SecxpathExpr) secEvaluate_s(root xpath.NodeNavigator) interface{} {
	if secIntercept.IsDisable() {
		return e.secEvaluate_s(root)
	}
	logger.Debugln("------------ xpath.ExprEvaluate-hook", "in hook")
	eventID := secIntercept.TraceXpathOperation(e.Expr.String())
	a := e.secEvaluate_s(root)
	if a != nil {
		secIntercept.SendExitEvent(eventID, nil)
	}
	return a
}

//go:noinline
func (e *SecxpathExpr) secEvaluate(root xpath.NodeNavigator) interface{} {
	if secIntercept.IsDisable() {
		return e.secEvaluate_s(root)
	}
	logger.Debugln("------------ xpath.ExprEvaluate-hook", "in hook")
	eventID := secIntercept.TraceXpathOperation(e.Expr.String())
	a := e.secEvaluate_s(root)
	if a != nil {
		secIntercept.SendExitEvent(eventID, nil)
	}
	return a
}

func applyXpathHooks() {
	logger.Infoln("xpath pluginStart Started")
	e := secIntercept.HookWrapInterface((*xpath.Expr).Evaluate, (*SecxpathExpr).secEvaluate, (*SecxpathExpr).secEvaluate_s)
	secIntercept.IsHookedLog("(*xpath.Expr).Evaluate", e)

	logger.Infoln("xpath pluginStart completed")
}
func init() {
	if !secIntercept.IsAgentInitializedForHook() || secIntercept.IsForceDisable() || !secIntercept.IsHookingoIsSupported() {
		return
	}
	applyXpathHooks()
}
