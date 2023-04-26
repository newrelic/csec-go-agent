// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package csec_antchfx_jsonquery

import (
	"reflect"

	"github.com/antchfx/jsonquery"
	"github.com/antchfx/xpath"
	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

var logger = secIntercept.GetLogger("csec_antchfx_jsonquery")

//go:noinline
func secQuerySelectorAll_s(top *jsonquery.Node, selector *xpath.Expr) []*jsonquery.Node {
	if secIntercept.IsDisable() {
		return secQuerySelectorAll_s(top, selector)
	}
	logger.Debugln("------------ Json.JsonquerySelectorAll", "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		eventID = secIntercept.TraceXpathOperation(fv.String())
	}
	res := secQuerySelectorAll_s(top, selector)
	if res != nil {
		secIntercept.SendExitEvent(eventID, nil)
	}
	return res
}

//go:noinline
func secQuerySelectorAll(top *jsonquery.Node, selector *xpath.Expr) []*jsonquery.Node {
	if secIntercept.IsDisable() {
		return secQuerySelectorAll_s(top, selector)
	}
	logger.Debugln("------------ Json.JsonquerySelectorAll", "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		eventID = secIntercept.TraceXpathOperation(fv.String())
	}
	res := secQuerySelectorAll_s(top, selector)
	if res != nil {
		secIntercept.SendExitEvent(eventID, nil)
	}
	return res
}

//go:noinline
func secQuerySelector_s(top *jsonquery.Node, selector *xpath.Expr) *jsonquery.Node {
	if secIntercept.IsDisable() {
		return secQuerySelector_s(top, selector)
	}
	logger.Debugln("------------ Json.JsonquerySelector", "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		eventID = secIntercept.TraceXpathOperation(fv.String())
	}
	a := secQuerySelector_s(top, selector)
	if a != nil {
		secIntercept.SendExitEvent(eventID, nil)
	}
	return a
}

//go:noinline
func secQuerySelector(top *jsonquery.Node, selector *xpath.Expr) *jsonquery.Node {
	if secIntercept.IsDisable() {
		return secQuerySelector_s(top, selector)
	}
	logger.Debugln("------------ Json.JsonquerySelector", "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		eventID = secIntercept.TraceXpathOperation(fv.String())
	}
	a := secQuerySelector_s(top, selector)
	if a != nil {
		secIntercept.SendExitEvent(eventID, nil)
	}
	return a
}

func applyXpathHooks() {
	logger.Infoln("Jsonquery pluginStart Started")
	e := secIntercept.HookWrap(jsonquery.QuerySelector, secQuerySelector, secQuerySelector_s)
	secIntercept.IsHookedLog("jsonquery.QuerySelector", e)

	e = secIntercept.HookWrap(jsonquery.QuerySelectorAll, secQuerySelectorAll, secQuerySelectorAll_s)
	secIntercept.IsHookedLog("jsonquery.QuerySelectorAll", e)

	logger.Infoln("jsonquery pluginStart completed")
}

func init() {
	if !secIntercept.IsAgentInitializedForHook() || secIntercept.IsForceDisable() || !secIntercept.IsHookingoIsSupported() {
		return
	}
	applyXpathHooks()
}
