// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_config

import (
	"os"

	logging "github.com/newrelic/csec-go-agent/internal/security_logs"
	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
)

var GlobalInfo *Info_struct = new(Info_struct)
var Secure secUtils.Secureiface
var SecureWS secUtils.SecureWSiface

type Info_struct struct {
	EventData           EventData
	EnvironmentInfo     EnvironmentInfo
	ApplicationInfo     RunningApplicationInfo
	InstrumentationData Instrumentation

	//user provied config
	Security        Security
	CurrentPolicy   Policy
	DefaultPolicy   Policy
	IsForceDisable  bool
	LinkingMetadata interface{}
	AccountID       string
	AgentRunId      string
}

// EventData used to track number of request
type EventData struct {
	EventDropCount   uint64
	EventProcessed   uint64
	EventSentCount   uint64
	HTTPRequestCount uint64
}

type EnvironmentInfo struct {
	ID                string
	NodeId            string
	NodeIp            string
	NodeName          string
	CollectorIp       string
	NodeGroupTags     []string
	RunningEnv        string
	Namespaces        string
	ContainerId       string
	PodId             string
	Wd                string
	Gopath            string
	Goarch            string
	Goos              string
	Goroot            string
	UserAppVersion    string
	UserAppTags       string
	EcsTaskId         string
	ImageId           string
	Image             string
	ContainerName     string
	EcsTaskDefinition string
}

type RunningApplicationInfo struct {
	AppName          string
	ApiAccessorToken string
	ProtectedServer  string
	AppUUID          string
	Sha256           string
	Size             string
	ContextPath      string
	Pid              string
	Cmd              string
	Cmdline          []string
	Ports            []int
	ServerIp         string
	Starttimestr     string
	BinaryPath       string
	ServerName       []string
}

type Instrumentation struct {
	HookCalledCount   uint64
	Hooked            bool
	TraceHooksApplied traceHooksApplied
}

type traceHooksApplied struct {
	Sql   bool
	Mongo bool
}

func InitDefaultConfig() {
	//init default info
	GlobalInfo.EventData = EventData{}
	GlobalInfo.InstrumentationData = Instrumentation{}
	GlobalInfo.EnvironmentInfo = EnvironmentInfo{}
	GlobalInfo.ApplicationInfo = RunningApplicationInfo{}
	GlobalInfo.LinkingMetadata = map[string]string{}

}

func UpdateGlobalConf(policy Policy, arg string) Policy {
	logging.EndStage("7", "Received and applied policy/configuration")
	logging.PrintInitlog(arg)
	GlobalInfo.DefaultPolicy = policy
	if !GlobalInfo.CurrentPolicy.Enforce {
		GlobalInfo.CurrentPolicy = policy
		return policy
	} else {
		return GlobalInfo.CurrentPolicy
	}
}

func InstantiateDefaultPolicy() {
	GlobalInfo.CurrentPolicy = GlobalInfo.DefaultPolicy
}

const forceDisable = "NEW_RELIC_SECURITY_FORCE_COMPLETE_DISABLE"

func isForceDisable() bool {
	return secUtils.CaseInsensitiveEquals(os.Getenv(forceDisable), "true")
}

func init() {
	InitDefaultConfig()
	if isForceDisable() {
		GlobalInfo.IsForceDisable = true
		return
	}
}
