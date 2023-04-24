// Copyright 2022 New Relic Corporation. All rights reserved.

package csec_robertkrimen_otto

import (
	secConfig "github.com/newrelic/csec-go-agent/security_config"
	"github.com/robertkrimen/otto"
	"testing"
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
