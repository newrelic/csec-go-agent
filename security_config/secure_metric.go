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

type stats struct {
	Submitted  uint64 `json:"submitted"`
	Completed  uint64 `json:"completed"`
	Rejected   uint64 `json:"rejected"`
	ErrorCount uint64 `json:"error"`
	sync.Mutex
}

func (e *stats) IncreaseEventSubmittedCount() {
	e.Lock()
	defer e.Unlock()
	e.Submitted++
}

func (e *stats) IncreaseCompletedCount() {
	e.Lock()
	defer e.Unlock()
	e.Completed++
}

func (e *stats) IncreaseEventRejectedCount() {
	e.Lock()
	defer e.Unlock()
	e.Rejected++
}

func (e *stats) IncreaseEventErrorCount() {
	e.Lock()
	defer e.Unlock()
	e.ErrorCount++
}

func (e *stats) Reset() {
	e.Lock()
	defer e.Unlock()
	e.ErrorCount = 0
	e.Rejected = 0
	e.Completed = 0
	e.Submitted = 0

}

type EventStats struct {
	EventSender       stats `json:"eventSender"`       // all events, urlMappings, ExitEvent, fuzzfail, app-info etc
	IastEvents        stats `json:"iastEvents"`        // only iast event
	Dispatcher        stats `json:"dispatcher"`        // RASP+IAST
	LowSeverityEvents stats `json:"lowSeverityEvents"` //LowSeverityEvents only N/A
	ExitEvents        stats `json:"exitEvents"`        // event event

}

func (e *EventStats) Reset() {
	e.EventSender.Reset()
	e.IastEvents.Reset()
	e.Dispatcher.Reset()
	e.LowSeverityEvents.Reset()
	e.ExitEvents.Reset()
}

func (e *EventStats) IncreaseEventSubmittedCount(eventType string) {
	incrementStat(eventType, e.EventSender.IncreaseEventSubmittedCount, e.IastEvents.IncreaseEventSubmittedCount, e.Dispatcher.IncreaseEventSubmittedCount, e.LowSeverityEvents.IncreaseEventSubmittedCount, e.ExitEvents.IncreaseEventSubmittedCount)
}

func (e *EventStats) IncreaseEventCompletedCount(eventType string) {
	incrementStat(eventType, e.EventSender.IncreaseCompletedCount, e.IastEvents.IncreaseCompletedCount, e.Dispatcher.IncreaseCompletedCount, e.LowSeverityEvents.IncreaseCompletedCount, e.ExitEvents.IncreaseCompletedCount)

}

func (e *EventStats) IncreaseEventRejectedCount(eventType string) {
	incrementStat(eventType, e.EventSender.IncreaseEventRejectedCount, e.IastEvents.IncreaseEventRejectedCount, e.Dispatcher.IncreaseEventRejectedCount, e.LowSeverityEvents.IncreaseEventRejectedCount, e.ExitEvents.IncreaseEventRejectedCount)

}

func (e *EventStats) IncreaseEventErrorCount(eventType string) {
	incrementStat(eventType, e.EventSender.IncreaseEventErrorCount, e.IastEvents.IncreaseEventErrorCount, e.Dispatcher.IncreaseEventErrorCount, e.LowSeverityEvents.IncreaseEventErrorCount, e.ExitEvents.IncreaseEventErrorCount)

}

func incrementStat(eventType string, f1, f2, f3, f4, f5 func()) {
	f1()
	switch eventType {
	case "iastEvent":
		f2()
		f3()
	case "raspEvent":
		f3()
	case "LowSeverityEvents":
		f4()
	case "exitEvent":
		f5()
	}
}

type DroppedEvent struct {
	UnsupportedContentType   uint64 `json:"unsupportedContentType"`
	RxssDetectionDeactivated uint64 `json:"rxssDetectionDeactivated"`
	sync.Mutex
}

func (d *DroppedEvent) IncreaseUnsupportedContentTypeCount() {
	d.Lock()
	defer d.Unlock()
	d.UnsupportedContentType++
}

func (d *DroppedEvent) IncreaseRxssDetectionDeactivatedCount() {
	d.Lock()
	defer d.Unlock()
	d.RxssDetectionDeactivated++
}

func (d *DroppedEvent) Reset() {
	d.Lock()
	defer d.Unlock()
	d.UnsupportedContentType = 0
	d.RxssDetectionDeactivated = 0
}
