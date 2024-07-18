// Copyright 2024 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package security_config

import (
	"sync"
)

type WebSocketConnectionStats struct {
	MessagesSent            uint64 `json:"messagesSent"`
	MessagesReceived        uint64 `json:"messagesReceived"`
	ConnectionReconnected   uint64 `json:"connectionReconnected"`
	ConnectionFailure       uint64 `json:"connectionFailure"`
	ReceivedReconnectAtWill uint64 `json:"receivedReconnectAtWill"`
	SendFailure             uint64 `json:"sendFailure"`
	sync.Mutex
}

func (wcs *WebSocketConnectionStats) IncreaseMessagesSent() {
	wcs.Lock()
	defer wcs.Unlock()
	wcs.MessagesSent++
}

func (wcs *WebSocketConnectionStats) IncreaseMessagesReceived() {
	wcs.Lock()
	defer wcs.Unlock()
	wcs.MessagesReceived++
}

func (wcs *WebSocketConnectionStats) IncreaseConnectionReconnected() {
	wcs.Lock()
	defer wcs.Unlock()
	wcs.ConnectionReconnected++
}

func (wcs *WebSocketConnectionStats) IncreaseConnectionFailure() {
	wcs.Lock()
	defer wcs.Unlock()
	wcs.ConnectionFailure++
}

func (wcs *WebSocketConnectionStats) IncreaseReceivedReconnectAtWill() {
	wcs.Lock()
	defer wcs.Unlock()
	wcs.ReceivedReconnectAtWill++
}

func (wcs *WebSocketConnectionStats) IncreaseSendFailure() {
	wcs.Lock()
	defer wcs.Unlock()
	wcs.SendFailure++
}
func (wcs *WebSocketConnectionStats) Reset() {
	wcs.Lock()
	defer wcs.Unlock()
	wcs.SendFailure = 0
	wcs.ReceivedReconnectAtWill = 0
	wcs.ConnectionFailure = 0
	wcs.ConnectionReconnected = 0
	wcs.MessagesReceived = 0
	wcs.MessagesSent = 0
}

type IastReplayRequest struct {
	ReceivedControlCommands uint64 `json:"receivedControlCommands"`
	PendingControlCommands  uint64 `json:"pendingControlCommands"`
	ReplayRequestGenerated  uint64 `json:"replayRequestGenerated"`
	ReplayRequestExecuted   uint64 `json:"replayRequestExecuted"`
	ReplayRequestSucceeded  uint64 `json:"replayRequestSucceeded"`
	ReplayRequestFailed     uint64 `json:"replayRequestFailed"`
	ReplayRequestRejected   uint64 `json:"replayRequestRejected"`
	sync.Mutex
}

func (iast *IastReplayRequest) IncreaseReceivedControlCommands() {
	iast.Lock()
	defer iast.Unlock()
	iast.ReceivedControlCommands++
}
func (iast *IastReplayRequest) IncreasePendingControlCommands() {
	iast.Lock()
	defer iast.Unlock()
	iast.PendingControlCommands++
}
func (iast *IastReplayRequest) IncreaseReplayRequestGenerated() {
	iast.Lock()
	defer iast.Unlock()
	iast.ReplayRequestGenerated++
}
func (iast *IastReplayRequest) IncreaseReplayRequestExecuted() {
	iast.Lock()
	defer iast.Unlock()
	iast.ReplayRequestExecuted++
}
func (iast *IastReplayRequest) IncreaseReplayRequestSucceeded() {
	iast.Lock()
	defer iast.Unlock()
	iast.ReplayRequestSucceeded++
}
func (iast *IastReplayRequest) IncreaseReplayRequestFailed() {
	iast.Lock()
	defer iast.Unlock()
	iast.ReplayRequestFailed++
}
func (iast *IastReplayRequest) IncreaseReplayRequestRejected() {
	iast.Lock()
	defer iast.Unlock()
	iast.ReplayRequestRejected++
}

func (iast *IastReplayRequest) Reset() {
	iast.Lock()
	defer iast.Unlock()
	iast.ReceivedControlCommands = 0
	iast.PendingControlCommands = 0
	iast.ReplayRequestGenerated = 0
	iast.ReplayRequestExecuted = 0
	iast.ReplayRequestSucceeded = 0
	iast.ReplayRequestFailed = 0
	iast.ReplayRequestRejected = 0
}
