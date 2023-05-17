// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package newrelic_security_agent

import (
	"net/http"

	sec_intercept "github.com/newrelic/csec-go-agent/security_intercept"
)

type securityAgent struct {
}

func (t securityAgent) RefreshState(connectionData map[string]string) bool {
	sec_intercept.UpdateLinkData(connectionData)
	return true
}

func (t securityAgent) DeactivateSecurity() {
	sec_intercept.DeactivateSecurity()
}

func (t securityAgent) SendEvent(caseType string, data ...interface{}) interface{} {
	return sec_intercept.SendEvent(caseType, data...)
}

func (t securityAgent) SendExitEvent(secureAgentevent interface{}, err error) {
	sec_intercept.SendExitEvent(secureAgentevent, err)
}

func (t securityAgent) IsSecurityActive() bool {
	return !sec_intercept.IsDisable() || !sec_intercept.IsForceDisable()
}

func (t securityAgent) DistributedTraceHeaders(hdrs *http.Request, secureAgentevent interface{}) {
	sec_intercept.DistributedTraceHeaders(hdrs, secureAgentevent)

}
