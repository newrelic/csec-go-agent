// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_utils

import (
	"net"
)

type Secureiface interface {
	AssociateOutboundRequest(string, string, string)
	SecurePrepareStatement(string, string)
	SecureExecPrepareStatement(string, interface{}) *EventTracker
	GetRequest() *Info_req
	AssociateInboundRequest(*Info_req)
	DissociateInboundRequest()
	HookWrap(interface{}, interface{}, interface{}) error
	HookWrapInterface(interface{}, interface{}, interface{}) error
	HookWrapRaw(uintptr, interface{}, interface{}) error
	HookWrapRawNamed(string, interface{}, interface{}) (string, error)
	AssociateGoRoutine(caller, callee int64)
	AssociateGrpcDataBytes([]byte) bool
	InitSyms() error
	CalculateOutboundApiId()
	AssociateGrpcData(string, string)
	DisassociateGrpcData()
	AssociateGrpcQueryParam(interface{})
	SendExitEvent(*EventTracker)
	AssociateFastHttpData(net.Conn)
	DisassociateFastHttpData()
	GetFastHttpData() net.Conn
	SendEvent(category string, args interface{}) *EventTracker
	GetFuzzHeader() string
	NewGoroutineLinker(interface{})
	NewGoroutine() interface{}
}

// ---------------------------------------------------
// interface: websocket interface
// ---------------------------------------------------
type SecureWSiface interface {
	RegisterEvent([]byte)
	GetStatus() bool
	ReconnectAtAgentRefresh()
	ReconnectAtWill()
	CloseWSConnection()
}
