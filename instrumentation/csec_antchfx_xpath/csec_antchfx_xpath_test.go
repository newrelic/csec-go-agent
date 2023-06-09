// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package csec_antchfx_xpath

import (
	"fmt"
	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
	_ "github.com/newrelic/csec-go-agent"
	"strings"
	"testing"

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

func TestXpathEvallHook(t *testing.T) {

	secConfig.RegisterListener()
	doc, _ := xmlquery.Parse(strings.NewReader(s))

	expr, err := xpath.Compile(fmt.Sprintf(".//employee[firstName[text()='%s']]", "Lokesh"))
	if err != nil {
		t.Error(err)
	}

	expr.Evaluate(xmlquery.CreateXPathNavigator(doc))

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[.//employee[firstName[text()='Lokesh']]]", CaseType: secConfig.XPATH},
	}

	secConfig.ValidateResult(expectedData, t)
}
