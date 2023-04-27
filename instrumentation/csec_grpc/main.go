// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package csec_grpc

import (
	"net"

	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
	"google.golang.org/grpc"
	_ "google.golang.org/protobuf/proto"
)

var logger = secIntercept.GetLogger("grpc")

type SecGrpcServe struct {
	grpc.Server
}

//go:noinline
func (k *SecGrpcServe) secServe_s(l net.Listener) error {
	if secIntercept.IsDisable() {
		return k.secServe_s(l)
	}
	logger.Debugln("------------ Port Detection----------")
	//Process start
	if l != nil {
		ipString := l.Addr().String()
		logger.Debugln("ipString : ", ipString)
		secIntercept.AssociateApplicationPort(ipString)
	}
	secIntercept.ProcessInit("gRPC")
	e := k.secServe_s(l)
	return e
}

//go:noinline
func (k *SecGrpcServe) secServe(l net.Listener) error {
	if secIntercept.IsDisable() {
		return k.secServe_s(l)
	}
	logger.Debugln("------------ Port Detection----------")
	if l != nil {
		ipString := l.Addr().String()
		logger.Debugln("ipString : ", ipString)
		secIntercept.AssociateApplicationPort(ipString)
	}
	secIntercept.ProcessInit("gRPC")
	e := k.secServe_s(l)
	return e
}

func init() {
	if !secIntercept.IsAgentInitializedForHook() || secIntercept.IsForceDisable() || !secIntercept.IsHookingoIsSupported() {
		return
	}

	e := secIntercept.HookWrapInterface((*grpc.Server).Serve, (*SecGrpcServe).secServe, (*SecGrpcServe).secServe_s)
	secIntercept.IsHookedLog("(*grpc.Server).Serve", e)
	secIntercept.InitGrpsFuzzRestClient(SecGrpcFuzz{})
}
