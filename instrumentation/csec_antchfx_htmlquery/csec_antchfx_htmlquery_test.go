// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package csec_antchfx_htmlquery

import (
	"strings"
	"testing"

	"github.com/antchfx/htmlquery"

	secConfig "github.com/newrelic/csec-go-agent/security_config"
)

var htmlText = `
<!doctype html>
<html>
<head>
    <title>Example Domain</title>

    <meta charset="utf-8" />
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style type="text/css">
    body {
        background-color: #f0f0f2;
        margin: 0;
        padding: 0;
        font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
        
    }
    div {
        width: 600px;
        margin: 5em auto;
        padding: 2em;
        background-color: #fdfdff;
        border-radius: 0.5em;
        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);
    }
    a:link, a:visited {
        color: #38488f;
        text-decoration: none;
    }
    @media (max-width: 700px) {
        div {
            margin: 0 auto;
            width: auto;
        }
    }
    </style>    
</head>

<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
</div>
</body>
</html>
`

func TestHTMLQueryHook(t *testing.T) {
	secConfig.RegisterListener()

	doc, err := htmlquery.Parse(strings.NewReader(htmlText))
	if err != nil {
		t.Error(err)
	}

	_, err = htmlquery.Query(doc, "//title")
	if err != nil {
		t.Error(err)
	}

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[//title]", CaseType: secConfig.XPATH},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestHTMLQueryallHook(t *testing.T) {
	secConfig.RegisterListener()

	doc, err := htmlquery.Parse(strings.NewReader(htmlText))
	if err != nil {
		t.Error(err)
	}
	_, err = htmlquery.QueryAll(doc, "//p")
	if err != nil {
		t.Error(err)
	}

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[//p]", CaseType: secConfig.XPATH},
	}

	secConfig.ValidateResult(expectedData, t)
}
