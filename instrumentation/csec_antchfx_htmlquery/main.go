// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package csec_antchfx_htmlquery

import (
	"reflect"

	"github.com/antchfx/htmlquery"
	"github.com/antchfx/xpath"
	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
	"golang.org/x/net/html"
)

var logger = secIntercept.GetLogger("csec_antchfx_htmlquery")

//go:noinline
func secQuerySelectorAll_s(top *html.Node, selector *xpath.Expr) []*html.Node {
	if secIntercept.IsDisable() {
		return secQuerySelectorAll_s(top, selector)
	}
	logger.Debugln("------------ html.HtmlquerySelectorAll", "in hook")
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
func secQuerySelectorAll(top *html.Node, selector *xpath.Expr) []*html.Node {
	if secIntercept.IsDisable() {
		return secQuerySelectorAll_s(top, selector)
	}
	logger.Debugln("------------ html.HtmlquerySelectorAll", "in hook")
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
func secQuerySelector_s(top *html.Node, selector *xpath.Expr) *html.Node {
	if secIntercept.IsDisable() {
		return secQuerySelector_s(top, selector)
	}
	logger.Debugln("------------ html.HtmlquerySelector", "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		eventID = secIntercept.TraceXpathOperation(fv.String())
	}
	res := secQuerySelector_s(top, selector)
	if res != nil {
		secIntercept.SendExitEvent(eventID, nil)
	}
	return res
}

//go:noinline
func secQuerySelector(top *html.Node, selector *xpath.Expr) *html.Node {
	if secIntercept.IsDisable() {
		return secQuerySelector_s(top, selector)
	}
	logger.Debugln("------------ html.HtmlquerySelector", "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		eventID = secIntercept.TraceXpathOperation(fv.String())
	}
	res := secQuerySelector_s(top, selector)
	if res != nil {
		secIntercept.SendExitEvent(eventID, nil)
	}
	return res
}

func applyXpathHooks() {
	logger.Infoln("Htmlquery pluginStart Started")
	e := secIntercept.HookWrap(htmlquery.QuerySelector, secQuerySelector, secQuerySelector_s)
	secIntercept.IsHookedLog("htmlquery.QuerySelector", e)

	e = secIntercept.HookWrap(htmlquery.QuerySelectorAll, secQuerySelectorAll, secQuerySelectorAll_s)
	secIntercept.IsHookedLog("htmlquery.QuerySelectorAll", e)

	logger.Infoln("htmlquery pluginStart completed")
}
func init() {
	if !secIntercept.IsAgentInitializedForHook() || secIntercept.IsForceDisable() || !secIntercept.IsHookingoIsSupported() {
		return
	}
	applyXpathHooks()
}
