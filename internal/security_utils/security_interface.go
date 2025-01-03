// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

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
	AssociateGrpcInfo(bool, bool)
	AssociategraphqlInfo(bool, bool)
	InitSyms() error
	CalculateOutboundApiId()
	AssociateGrpcData(string, string)
	DisassociateGrpcData()
	AssociateGrpcQueryParam(interface{}, string, string)
	SendExitEvent(*EventTracker)
	AssociateFastHttpData(net.Conn)
	DisassociateFastHttpData()
	GetFastHttpData() net.Conn
	SendEvent(caseType, eventCategory string, args interface{}) *EventTracker
	SendLowSeverityEvent(caseType, eventCategory string, args interface{}) *EventTracker
	GetFuzzHeader() string
	GetTmpFiles() []string
	NewGoroutineLinker(interface{})
	NewGoroutine() interface{}
	SendPanicEvent(string)
	Send5xxEvent(int)
	CleanLowSeverityEvent()
}

// ---------------------------------------------------
// interface: websocket interface
// ---------------------------------------------------
type SecureWSiface interface {
	RegisterEvent([]byte, string, string)
	GetStatus() bool
	ReconnectAtAgentRefresh()
	ReconnectAtWill()
	CloseWSConnection()
	SendPriorityEvent([]byte)
	AddCompletedRequests(string, string)
	PendingEvent() int
	PendingFuzzTask() uint64
}
