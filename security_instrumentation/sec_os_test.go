// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package security_instrumentation

import (
	"os"
	"os/exec"
	"testing"

	secConfig "github.com/newrelic/csec-go-agent/security_config"
)

func TestOSOpenHook(t *testing.T) {
	secConfig.RegisterListener()

	_, err := os.Open("/etc/passwd")
	if err != nil {
		t.Error(err)
	}
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[/etc/passwd]", CaseType: secConfig.FILE},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestOSFileOpenHook(t *testing.T) {
	secConfig.RegisterListener()

	_, err := os.OpenFile("/etc/passwd", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		t.Error(err)
	}
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[/etc/passwd]", CaseType: secConfig.FILE},
	}
	secConfig.ValidateResult(expectedData, t)
}
func TestOSRemoveHook(t *testing.T) {
	secConfig.RegisterListener()
	os.Remove("/tmp/file-remove-test/abc.txt")
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[/tmp/file-remove-test/abc.txt]", CaseType: secConfig.FILE},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestOSStartProcessHook(t *testing.T) {
	secConfig.RegisterListener()
	cmd := exec.Command("ls")
	err := cmd.Start()
	if err != nil {
		t.Error(err)
	}
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[ls]", CaseType: secConfig.SYSTEM},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestSystemExecStartHook(t *testing.T) {
	secConfig.RegisterListener()
	cmd := exec.Command("abc")
	err := cmd.Start()
	if err != nil {
		t.Error(err)
	}
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[abc]", CaseType: secConfig.SYSTEM},
	}
	secConfig.ValidateResult(expectedData, t)
}
