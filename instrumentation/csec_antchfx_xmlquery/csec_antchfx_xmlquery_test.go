// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package csec_antchfx_xmlquery

import (
	"fmt"
	"strings"
	"testing"

	"github.com/antchfx/xmlquery"
	_ "github.com/newrelic/csec-go-agent"

	secConfig "github.com/newrelic/csec-go-agent/security_config"
)

var s = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<employees>
    <employee id="2">
        <firstName>Lokesh</firstName>
        <lastName>Gupta</lastName>
        <department>
            <id>101</id>
            <name>IT</name>
        </department>
    </employee>
</employees>`

func TestXmlQueryallHook(t *testing.T) {

	secConfig.RegisterListener()

	items := fmt.Sprintf(".//employee[firstName[text()='%s']]", "Lokesh")
	doc, err := xmlquery.Parse(strings.NewReader(s))
	if err != nil {
		t.Error(err)
	}

	_, err = xmlquery.QueryAll(doc, items)
	if err != nil {
		t.Error(err)
	}

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[.//employee[firstName[text()='Lokesh']]]", CaseType: secConfig.XPATH},
	}

	secConfig.ValidateResult(expectedData, t)
}

func TestXmlQueryHook(t *testing.T) {
	secConfig.RegisterListener()

	items := fmt.Sprintf(".//employee[firstName[text()='%s']]", "Lokesh")
	doc, err := xmlquery.Parse(strings.NewReader(s))
	if err != nil {
		t.Error(err)
	}
	_, err = xmlquery.Query(doc, items)
	if err != nil {
		t.Error(err)
	}

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[.//employee[firstName[text()='Lokesh']]]", CaseType: secConfig.XPATH},
	}

	secConfig.ValidateResult(expectedData, t)
}
