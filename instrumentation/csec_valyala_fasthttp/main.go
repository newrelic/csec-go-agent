// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package csec_valyala_fasthttp

import (
	"net"

	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
	"github.com/valyala/fasthttp"
)

var logger = secIntercept.GetLogger("fasthttp")

type SecServer struct {
	fasthttp.Server
}

//go:noinline
func (s *SecServer) secServe(ln net.Listener) error {
	if secIntercept.IsDisable() {
		return s.secServe_s(ln)
	}
	logger.Debugln("Hook Called : ", "*fasthttp.Server.Serve")
	if ln != nil {
		ipString := ln.Addr().String()
		logger.Debugln("ipString:", ipString)
		secIntercept.AssociateApplicationPort(ipString)
	}
	secIntercept.ProcessInit("FastHTTP")
	return s.secServe_s(ln)
}

//go:noinline
func (s *SecServer) secServe_s(ln net.Listener) error {
	if secIntercept.IsDisable() {
		return s.secServe_s(ln)
	}
	logger.Debugln("Hook Called : ", "*fasthttp.Server.Serve")
	if ln != nil {
		ipString := ln.Addr().String()
		logger.Debugln("ipString:", ipString)
		secIntercept.AssociateApplicationPort(ipString)
	}
	secIntercept.ProcessInit("FastHTTP")
	return s.secServe_s(ln)
}

func hook() {
	e := secIntercept.HookWrapInterface((*fasthttp.Server).Serve, (*SecServer).secServe, (*SecServer).secServe_s)
	secIntercept.IsHookedLog("(*fasthttp.Server).Serve", e)
	logger.Infoln("fastHttp pluginStart completed")

}
func init() {

	if !secIntercept.IsAgentInitializedForHook() || secIntercept.IsForceDisable() || !secIntercept.IsHookingoIsSupported() {
		return
	}
	hook()

}
