// Copyright 2022 New Relic Corporation. All rights reserved.

package newrelic

import (
	secConfig "github.com/newrelic/csec-go-agent/security_config"
	_ "github.com/newrelic/csec-go-agent/security_instrumentation"
)

type SecurityAgentConfig struct {
	secConfig.Security
}

func InitSecurityAgent(securityAgentConfig secConfig.Security, appName string, license string, isDebugLog bool) securityAgent {
	initSecurityAgent(appName, license, isDebugLog, securityAgentConfig)
	return securityAgent{}
}
