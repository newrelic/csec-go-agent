// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package security_instrumentation

import (
	"net"
	"net/http"

	logging "github.com/newrelic/csec-go-agent/internal/security_logs"
	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

type SecServe struct {
	http.Server
}

//go:noinline
func (k *SecServe) secServer_s(l net.Listener) error {
	if secIntercept.IsDisable() {
		return k.secServer_s(l)
	}
	logger.Infoln("Hook Called : ", "(*http.Server).Serve")
	if l != nil {
		ipString := l.Addr().String()
		logger.Debugln("ipString:", ipString)
		secIntercept.AssociateApplicationPort(ipString)
		secIntercept.ProcessInit("net/http")
	}
	return k.secServer_s(l)
}

//go:noinline
func (k *SecServe) secServer(l net.Listener) error {
	if secIntercept.IsDisable() {
		return k.secServer_s(l)
	}
	logger.Infoln("Hook Called : ", "(*http.Server).Serve")
	if l != nil {
		ipString := l.Addr().String()
		logger.Debugln("ipString:", ipString)
		secIntercept.AssociateApplicationPort(ipString)
		secIntercept.ProcessInit("net/http")
	}
	return k.secServer_s(l)
}

func initServerHook() {
	e := secIntercept.HookWrapInterface((*http.Server).Serve, (*SecServe).secServer, (*SecServe).secServer_s)
	logging.IsHooked("(*http.Server).Serve", e)
}
