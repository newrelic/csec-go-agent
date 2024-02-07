// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package csec_robertkrimen_otto

import (
	"testing"

	secConfig "github.com/newrelic/csec-go-agent/security_config"
	"github.com/robertkrimen/otto"
)

func TestOttoRunHook(t *testing.T) {
	secConfig.RegisterListener()

	vm := otto.New()
	vm.Run("console.log('hello')")

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[console.log('hello')]", CaseType: secConfig.JS_INJECTION},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestOttoEvalHook(t *testing.T) {
	secConfig.RegisterListener()

	vm := otto.New()
	vm.Eval("console.log('hello')")

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[console.log('hello')]", CaseType: secConfig.JS_INJECTION},
	}
	secConfig.ValidateResult(expectedData, t)
}
