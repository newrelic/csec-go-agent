// Copyright 2022 New Relic Corporation. All rights reserved.

package csec_antchfx_xmlquery

import (
	"reflect"

	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

var logger = secIntercept.GetLogger("csec_antchfx_xmlquery")

//go:noinline
func secQuerySelectorAll_s(top *xmlquery.Node, selector *xpath.Expr) []*xmlquery.Node {
	if secIntercept.IsDisable() {
		return secQuerySelectorAll_s(top, selector)
	}
	logger.Debugln("------------ xpath.QuerySelectorAll", "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		eventID = secIntercept.TraceXpathOperation(fv.String())
	}
	nodes := secQuerySelectorAll_s(top, selector)
	if nodes != nil {
		secIntercept.SendExitEvent(eventID, nil)
	}
	return nodes
}

//go:noinline
func secQuerySelectorAll(top *xmlquery.Node, selector *xpath.Expr) []*xmlquery.Node {
	if secIntercept.IsDisable() {
		return secQuerySelectorAll_s(top, selector)
	}
	logger.Debugln("------------ xpath.QuerySelectorAll", "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		eventID = secIntercept.TraceXpathOperation(fv.String())
	}
	nodes := secQuerySelectorAll_s(top, selector)
	if nodes != nil {
		secIntercept.SendExitEvent(eventID, nil)
	}
	return nodes
}

//go:noinline
func secQuerySelector_s(top *xmlquery.Node, selector *xpath.Expr) *xmlquery.Node {
	if secIntercept.IsDisable() {
		return secQuerySelector_s(top, selector)
	}
	logger.Debugln("------------ xpath.QuerySelector", "in hook")
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
func secQuerySelector(top *xmlquery.Node, selector *xpath.Expr) *xmlquery.Node {
	if secIntercept.IsDisable() {
		return secQuerySelector_s(top, selector)
	}
	logger.Debugln("------------ xpath.QuerySelector", "in hook")
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
	logger.Infoln("xmlquery pluginStart Started")
	e := secIntercept.HookWrap(xmlquery.QuerySelector, secQuerySelector, secQuerySelector_s)
	secIntercept.IsHookedLog("xmlquery.QuerySelector", e)

	e = secIntercept.HookWrap(xmlquery.QuerySelectorAll, secQuerySelectorAll, secQuerySelectorAll_s)
	secIntercept.IsHookedLog("xmlquery.QuerySelectorAll", e)

	logger.Infoln("xmlquery pluginStart completed")
}
func init() {
	if !secIntercept.IsAgentInitializedForHook() || secIntercept.IsForceDisable() || !secIntercept.IsHookingoIsSupported() {
		return
	}
	applyXpathHooks()
}
