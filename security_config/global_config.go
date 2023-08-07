// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_config

import (
	"math"
	"os"
	"strconv"
	"sync"

	logging "github.com/newrelic/csec-go-agent/internal/security_logs"
	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
)

var GlobalInfo *Info_struct = new(Info_struct)
var Secure secUtils.Secureiface
var SecureWS secUtils.SecureWSiface

type Info_struct struct {
	EventData           eventData
	EnvironmentInfo     EnvironmentInfo
	ApplicationInfo     runningApplicationInfo
	InstrumentationData Instrumentation

	securityMutex sync.Mutex
	security      Security

	ploicyMutex    sync.Mutex
	currentPolicy  Policy
	defaultPolicy  Policy
	isForceDisable bool

	MetaData metaData
}

func (info *Info_struct) GetCurrentPolicy() Policy {
	info.ploicyMutex.Lock()
	defer info.ploicyMutex.Unlock()
	return info.currentPolicy
}
func (info *Info_struct) SetCurrentPolicy(policy Policy) {
	info.ploicyMutex.Lock()
	defer info.ploicyMutex.Unlock()
	info.currentPolicy = policy
}

func (info *Info_struct) GetdefaultPolicy() Policy {
	info.ploicyMutex.Lock()
	defer info.ploicyMutex.Unlock()
	return info.defaultPolicy
}

func (info *Info_struct) SetdefaultPolicy(policy Policy) {
	info.ploicyMutex.Lock()
	defer info.ploicyMutex.Unlock()
	info.defaultPolicy = policy
}

func (info *Info_struct) IsForceDisable() bool {
	info.ploicyMutex.Lock()
	defer info.ploicyMutex.Unlock()
	return info.isForceDisable
}
func (info *Info_struct) SetForceDisable(b bool) {
	info.ploicyMutex.Lock()
	defer info.ploicyMutex.Unlock()
	info.isForceDisable = b
}

func (info *Info_struct) IsIASTEnable() bool {
	info.ploicyMutex.Lock()
	defer info.ploicyMutex.Unlock()
	return info.currentPolicy.VulnerabilityScan.Enabled && GlobalInfo.currentPolicy.VulnerabilityScan.IastScan.Enabled
}

// for security config
func (info *Info_struct) IsSecurityEnabled() bool {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.Enabled
}
func (info *Info_struct) SetSecurityEnabled(isenabled bool) {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	info.security.Enabled = isenabled
}
func (info *Info_struct) SetSecurityAgentEnabled(isenabled bool) {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	info.security.Agent.Enabled = isenabled
}

func (info *Info_struct) SetSecurity(security Security) {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	info.security = security
}

func (info *Info_struct) IsRxssEnabled() bool {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.Detection.Rxss.Enabled
}

func (info *Info_struct) SecurityHomePath() string {
	return info.security.SecurityHomePath
}
func (info *Info_struct) SetSecurityHomePath(path string) {
	info.security.SecurityHomePath = path
}

func (info *Info_struct) ValidatorServiceUrl() string {
	return info.security.Validator_service_url
}
func (info *Info_struct) SetValidatorServiceUrl(path string) {
	info.security.Validator_service_url = path
}

func (info *Info_struct) SecurityMode() string {
	return info.security.Mode
}

type metaData struct {
	linkingMetadata interface{}
	accountID       string
	agentRunId      string
	sync.Mutex
}

func (m *metaData) GetAccountID() string {
	m.Lock()
	defer m.Unlock()
	return m.accountID
}

func (m *metaData) SetAccountID(value string) {
	m.Lock()
	defer m.Unlock()
	m.accountID = value
}

func (m *metaData) GetAgentRunId() string {
	m.Lock()
	defer m.Unlock()
	return m.agentRunId
}

func (m *metaData) SetAgentRunId(value string) {
	m.Lock()
	defer m.Unlock()
	m.agentRunId = value
}

func (m *metaData) GetLinkingMetadata() interface{} {
	m.Lock()
	defer m.Unlock()
	return m.linkingMetadata
}

func (m *metaData) SetLinkingMetadata(value interface{}) {
	m.Lock()
	defer m.Unlock()
	m.linkingMetadata = value
}

// EventData used to track number of request
type eventData struct {
	eventDropCount   uint64
	eventProcessed   uint64
	eventSentCount   uint64
	httpRequestCount uint64
	sync.Mutex
}

func (e *eventData) GetEventDropCount() uint64 {
	if e == nil {
		return 0
	}
	e.Lock()
	defer e.Unlock()
	return e.eventDropCount
}

func (e *eventData) SetEventDropCount(value uint64) {
	if e == nil {
		return
	}
	e.Lock()
	defer e.Unlock()
	e.eventDropCount = value
}

func (e *eventData) IncreaseEventDropCount() {
	if e == nil {
		return
	}
	e.Lock()
	defer e.Unlock()

	e.eventDropCount++
	if e.eventDropCount == 0 {
		e.eventDropCount = math.MaxUint64
	}
}

func (e *eventData) GetEventProcessed() uint64 {
	if e == nil {
		return 0
	}
	e.Lock()
	defer e.Unlock()
	return e.eventProcessed
}

func (e *eventData) SetEventProcessed(value uint64) {
	if e == nil {
		return
	}
	e.Lock()
	defer e.Unlock()
	e.eventProcessed = value
}

func (e *eventData) IncreaseEventProcessed() {
	if e == nil {
		return
	}
	e.Lock()
	defer e.Unlock()

	e.eventProcessed++
	if e.eventProcessed == 0 {
		e.eventProcessed = math.MaxUint64
	}
}

func (e *eventData) GetEventSentCount() uint64 {
	if e == nil {
		return 0
	}
	e.Lock()
	defer e.Unlock()
	return e.eventSentCount
}

func (e *eventData) SetEventSentCount(value uint64) {
	if e == nil {
		return
	}
	e.Lock()
	defer e.Unlock()

	e.eventSentCount = value
}

func (e *eventData) IncreaseEventSentCount() {
	if e == nil {
		return
	}
	e.Lock()
	defer e.Unlock()

	e.eventSentCount++
	if e.eventSentCount == 0 {
		e.eventSentCount = math.MaxUint64
	}
}

func (e *eventData) GetHttpRequestCount() uint64 {
	var out uint64
	if e == nil {
		return out
	}
	e.Lock()
	defer e.Unlock()
	return e.httpRequestCount
}

func (e *eventData) SetHttpRequestCount(value uint64) {
	if e == nil {
		return
	}
	e.Lock()
	defer e.Unlock()
	e.httpRequestCount = value
}

func (e *eventData) IncreaseHttpRequestCount() {
	if e == nil {
		return
	}
	e.Lock()
	defer e.Unlock()

	e.httpRequestCount++
	if e.httpRequestCount == 0 {
		e.httpRequestCount = math.MaxUint64
	}
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

type runningApplicationInfo struct {
	sync.Mutex
	appName          string
	apiAccessorToken string
	protectedServer  string
	appUUID          string
	sha256           string
	size             string
	contextPath      string
	pid              string
	Cmd              string
	cmdline          []string
	ports            []int
	ServerIp         string
	starttimestr     string
	binaryPath       string
	serverName       []string
	apiEndPoints     map[string]string
}

func (r *runningApplicationInfo) GetAppName() string {
	return r.appName
}

func (r *runningApplicationInfo) SetAppName(value string) {
	r.appName = value
}

func (r *runningApplicationInfo) GetApiAccessorToken() string {
	return r.apiAccessorToken
}

func (r *runningApplicationInfo) SetApiAccessorToken(value string) {
	r.apiAccessorToken = value
}

func (r *runningApplicationInfo) GetProtectedServer() string {
	return r.protectedServer
}

func (r *runningApplicationInfo) SetProtectedServer(value string) {
	r.protectedServer = value
}

func (r *runningApplicationInfo) GetAppUUID() string {
	return r.appUUID
}

func (r *runningApplicationInfo) SetAppUUID(value string) {
	r.appUUID = value
}

func (r *runningApplicationInfo) GetSha256() string {
	return r.sha256
}

func (r *runningApplicationInfo) SetSha256(value string) {
	r.sha256 = value
}

func (r *runningApplicationInfo) GetSize() string {
	var out string
	if r == nil {
		return out
	}
	return r.size
}

func (r *runningApplicationInfo) SetSize(value string) {
	r.size = value
}

func (r *runningApplicationInfo) GetContextPath() string {
	return r.contextPath
}

func (r *runningApplicationInfo) SetContextPath(value string) {
	r.contextPath = value
}

func (r *runningApplicationInfo) GetPid() string {
	return r.pid
}

func (r *runningApplicationInfo) SetPid(value string) {
	r.pid = value
}

func (r *runningApplicationInfo) GetCmd() string {
	return r.Cmd
}

func (r *runningApplicationInfo) SetCmd(value string) {
	r.Cmd = value
}

func (r *runningApplicationInfo) GetCmdline() []string {
	return r.cmdline
}

func (r *runningApplicationInfo) SetCmdline(value []string) {
	r.cmdline = value
}

func (r *runningApplicationInfo) GetPorts() []int {
	return r.ports
}

func (r *runningApplicationInfo) SetPorts(value int) {
	r.ports = append(r.ports, value)
}

func (r *runningApplicationInfo) GetServerIp() string {
	return r.ServerIp
}

func (r *runningApplicationInfo) SetServerIp(value string) {
	r.ServerIp = value
}

func (r *runningApplicationInfo) GetStarttimestr() string {
	return r.starttimestr
}

func (r *runningApplicationInfo) SetStarttimestr(value string) {
	r.starttimestr = value
}

func (r *runningApplicationInfo) GetBinaryPath() string {
	return r.binaryPath
}

func (r *runningApplicationInfo) SetBinaryPath(value string) {
	r.binaryPath = value
}

func (r *runningApplicationInfo) GetServerName() []string {
	r.Lock()
	defer r.Unlock()
	return r.serverName
}

func (r *runningApplicationInfo) SetServerName(value string) {
	r.Lock()
	defer r.Unlock()
	r.serverName = append(r.serverName, value)
}

func (r *runningApplicationInfo) GetApiEndPoints() map[string]string {
	r.Lock()
	defer r.Unlock()
	return r.apiEndPoints
}

func (r *runningApplicationInfo) SetApiEndPoints(uri, methods string) {
	r.Lock()
	defer r.Unlock()
	if r.apiEndPoints == nil {
		r.apiEndPoints = make(map[string]string, 0)
	}
	r.apiEndPoints[uri] = methods
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
	GlobalInfo.EventData = eventData{}
	GlobalInfo.InstrumentationData = Instrumentation{}
	GlobalInfo.EnvironmentInfo = EnvironmentInfo{}
	GlobalInfo.ApplicationInfo = runningApplicationInfo{}
	GlobalInfo.MetaData = metaData{}
	GlobalInfo.MetaData.linkingMetadata = map[string]string{}

}

func UpdateGlobalConf(policy Policy, arg string) Policy {
	logging.EndStage("7", "Received and applied policy/configuration")
	logging.PrintInitlog(arg)
	GlobalInfo.SetdefaultPolicy(policy)

	if !GlobalInfo.GetCurrentPolicy().Enforce {
		GlobalInfo.SetCurrentPolicy(policy)
		return policy
	} else {
		return GlobalInfo.GetCurrentPolicy()
	}
}

func InstantiateDefaultPolicy() {
	GlobalInfo.SetCurrentPolicy(GlobalInfo.GetdefaultPolicy())

}

const forceDisable = "NEW_RELIC_SECURITY_AGENT_ENABLED"

func isSecurityAgentEnabled() bool {
	if env := os.Getenv(forceDisable); env != "" {
		if b, err := strconv.ParseBool("false"); nil == err {
			return b
		}
	}
	return true
}

func init() {
	InitDefaultConfig()
	GlobalInfo.SetForceDisable(!isSecurityAgentEnabled())

}
