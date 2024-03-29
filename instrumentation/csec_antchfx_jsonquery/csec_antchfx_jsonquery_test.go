// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package csec_antchfx_jsonquery

import (
	"strings"
	"testing"

	"github.com/antchfx/jsonquery"

	secConfig "github.com/newrelic/csec-go-agent/security_config"
)

var json = `{
	"person":{
	   "name":"John",
	   "age":31,
	   "female":false,
	   "city":null,
	   "hobbies":[
		  "coding",
		  "eating",
		  "football"
	   ]
	}
 }`

func TestJSONQueryHook(t *testing.T) {
	secConfig.RegisterListener()

	doc, err := jsonquery.Parse(strings.NewReader(json))
	if err != nil {
		t.Error(err)
	}
	_, err = jsonquery.Query(doc, "//hobbies/*[1]")
	if err != nil {
		t.Error(err)
	}

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[//hobbies/*[1]]", CaseType: secConfig.XPATH},
	}

	secConfig.ValidateResult(expectedData, t)
}
func TestJSONQueryallHook(t *testing.T) {

	secConfig.RegisterListener()

	doc, err := jsonquery.Parse(strings.NewReader(json))
	if err != nil {
		t.Error(err)
	}

	_, err = jsonquery.QueryAll(doc, "//hobbies")
	if err != nil {
		t.Error(err)
	}

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[//hobbies]", CaseType: secConfig.XPATH},
	}

	secConfig.ValidateResult(expectedData, t)
}
