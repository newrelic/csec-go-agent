// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package security_config

import (
	"testing"
)

// Testing model
type TestArgs struct {
	Parameters interface{}
	CaseType   string
}

// Testing interface with required methods
type TestInterface interface {
	GetData() []TestArgs
	AddData(TestArgs)
	RemoveData()
}

// For Test interface initialisation
type TestData []TestArgs

// Interface object for Unit testing
var Testing TestInterface

// Stores the event data
var EventDataList []TestArgs

var XPATH = "XPATH"
var FILE = "FILE_OPERATION"
var SYSTEM = "SYSTEM_COMMAND"
var LDAP = "LDAP"
var SQL = "SQL_DB_COMMAND"
var JS_INJECTION = "JAVASCRIPT_INJECTION"
var NOSQL = "NOSQL_DB_COMMAND"

// Validates the event Data
func ValidateResult(expected []TestArgs, t *testing.T) {
	agentGenerated := GetEventData()
	if len(agentGenerated) < len(expected) {
		t.Error("Number of events Generated is unequal", agentGenerated, expected)
		return
	}

	var agentGeneratedMap = make(map[TestArgs]int)
	for _, key := range agentGenerated {
		agentGeneratedMap[key]++
	}
	for _, key := range expected {
		if count, ok := agentGeneratedMap[key]; ok && count > 0 {
			agentGeneratedMap[key]--
		} else {
			t.Error("Event Data not Matching")
			return
		}
	}
}

// Initialising the Testing object
func RegisterListener() {
	Testing = TestData{}
	GlobalInfo.Security.Enabled = true
	Testing.RemoveData()
}

// Returns the event data from agent side
func GetEventData() []TestArgs {
	return Testing.GetData()
}

// Empties the EventDataList
// func RemoveEventData() {
// 	Testing.RemoveData()
// }

// Checks if Testing interface object is initialised or not
func AddEventDataToListener(arg TestArgs) {
	if Testing != nil {
		Testing.AddData(arg)
		return
	}
}

// TestInterface method implementation
func (l TestData) AddData(arg TestArgs) {
	EventDataList = append(EventDataList, arg)
}

func (l TestData) GetData() []TestArgs {
	return EventDataList
}

func (l TestData) RemoveData() {
	EventDataList = nil
}
