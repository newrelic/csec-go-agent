// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package csec_ldap_v3

import (
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

var logger = secIntercept.GetLogger("ldap")

type SecConnstruct struct {
	ldap.Conn
}

// RFC4515 defines encoding for ldap
func UnescapeRFC4515validJSON(a string) string {
	logger.Debugln("ldapString incoming:", a)
	r := a
	r = strings.Replace(r, "\\2a", "*", -1)
	r = strings.Replace(r, "\\2A", "*", -1)
	r = strings.Replace(r, "\\28", "(", -1)
	r = strings.Replace(r, "\\29", ")", -1)
	logger.Debugln("ldapString Outgoing:", r)
	return r
}

//go:noinline
func (l *SecConnstruct) secSearch_s(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if secIntercept.IsDisable() {
		return l.secSearch_s(searchRequest)
	}
	logger.Debugln("------------ldap.Conn.Search-hook", "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if searchRequest != nil {
		xm := make(map[string]string, 0)
		xm["filter"] = UnescapeRFC4515validJSON((*searchRequest).Filter)
		eventID = secIntercept.TraceLdapOperation(xm)
	}
	res, err := l.secSearch_s(searchRequest)
	secIntercept.SendExitEvent(eventID, err)
	return res, err
}

//go:noinline
func (l *SecConnstruct) secSearch(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if secIntercept.IsDisable() {
		return l.secSearch_s(searchRequest)
	}
	logger.Debugln("------------ ldap.Conn.Search-hook", "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if searchRequest != nil {
		xm := make(map[string]string, 0)
		xm["filter"] = UnescapeRFC4515validJSON((*searchRequest).Filter)
		eventID = secIntercept.TraceLdapOperation(xm)
	}
	res, err := l.secSearch_s(searchRequest)
	secIntercept.SendExitEvent(eventID, err)
	return res, err
}

//go:noinline
func (l *SecConnstruct) secModify_s(mReq *ldap.ModifyRequest) error {
	if secIntercept.IsDisable() {
		return l.secModify_s(mReq)
	}
	logger.Debugln("------------ ldap.Conn.ldapConnModify-hook", "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if mReq != nil {
		xm := make(map[string]string, 0)
		xm["filter"] = UnescapeRFC4515validJSON((*mReq).DN)
		eventID = secIntercept.TraceLdapOperation(xm)
	}
	err := l.secModify_s(mReq)
	secIntercept.SendExitEvent(eventID, err)
	return err
}

//go:noinline
func (l *SecConnstruct) secModify(mReq *ldap.ModifyRequest) error {
	if secIntercept.IsDisable() {
		return l.secModify_s(mReq)
	}
	logger.Debugln("------------ ldap.Conn.ldapConnModify-hook", "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if mReq != nil {
		xm := make(map[string]string, 0)
		xm["filter"] = UnescapeRFC4515validJSON((*mReq).DN)
		eventID = secIntercept.TraceLdapOperation(xm)
	}
	err := l.secModify_s(mReq)
	secIntercept.SendExitEvent(eventID, err)
	return err
}

func hook() {
	e := secIntercept.HookWrapInterface((*ldap.Conn).Search, (*SecConnstruct).secSearch, (*SecConnstruct).secSearch_s)
	secIntercept.IsHookedLog("(*ldap.Conn).Search", e)
	e = secIntercept.HookWrapInterface((*ldap.Conn).Modify, (*SecConnstruct).secModify, (*SecConnstruct).secModify_s)
	secIntercept.IsHookedLog("(*ldap.Conn).Modify", e)
	return
}
func init() {
	if !secIntercept.IsAgentInitializedForHook() || secIntercept.IsForceDisable() || !secIntercept.IsHookingoIsSupported() {
		return
	}
	hook()
}
