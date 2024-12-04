// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package security_config

import (
	"os"
	"strconv"
	"sync"
	"time"

	logging "github.com/newrelic/csec-go-agent/internal/security_logs"
	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
)

var GlobalInfo *Info_struct = new(Info_struct)
var Secure secUtils.Secureiface
var SecureWS secUtils.SecureWSiface

type Info_struct struct {
	ApiData             *sync.Map
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

	WebSocketConnectionStats WebSocketConnectionStats
	IastReplayRequest        IastReplayRequest
	EventStats               EventStats
	DroppedEvent             DroppedEvent
	dealyAgentTill           time.Time
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

func (info *Info_struct) IsInsecureSettingsDisabled() bool {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.ExcludeFromIastScan.IastDetectionCategory.InsecureSettings
}
func (info *Info_struct) IsInvalidFileAccessDisabled() bool {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.ExcludeFromIastScan.IastDetectionCategory.InvalidFileAccess
}

func (info *Info_struct) IsSQLInjectionDisabled() bool {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.ExcludeFromIastScan.IastDetectionCategory.SQLInjection
}
func (info *Info_struct) IsNosqlInjectionDisabled() bool {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.ExcludeFromIastScan.IastDetectionCategory.NosqlInjection
}
func (info *Info_struct) IsLdapInjectionDisabled() bool {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.ExcludeFromIastScan.IastDetectionCategory.LdapInjection
}
func (info *Info_struct) IsJavascriptInjectionDisabled() bool {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.ExcludeFromIastScan.IastDetectionCategory.JavascriptInjection
}
func (info *Info_struct) IsCommandInjectionDisabled() bool {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.ExcludeFromIastScan.IastDetectionCategory.CommandInjection
}
func (info *Info_struct) IsXpathInjectionDisabled() bool {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.ExcludeFromIastScan.IastDetectionCategory.XpathInjection
}
func (info *Info_struct) IsSsrfDisabled() bool {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.ExcludeFromIastScan.IastDetectionCategory.Ssrf
}
func (info *Info_struct) IsRxssDisabled() bool {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.ExcludeFromIastScan.IastDetectionCategory.Rxss
}

func (info *Info_struct) SkipIastScanParameters() interface{} {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.ExcludeFromIastScan.HttpRequestParameters
}

func (info *Info_struct) SkipIastScanApi() []string {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.ExcludeFromIastScan.API
}

func (info *Info_struct) ScanScheduleDuration() int {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.ScanSchedule.Duration
}

func (info *Info_struct) ScanScheduleDelay() int {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.ScanSchedule.Delay
}

func (info *Info_struct) ScanScheduleAllowIastSampleCollection() bool {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.ScanSchedule.AllowIastSampleCollection
}

func (info *Info_struct) ScanScheduleSchedule() string {
	info.securityMutex.Lock()
	defer info.securityMutex.Unlock()
	return info.security.ScanSchedule.Schedule
}

func (info *Info_struct) SecurityHomePath() string {
	return info.security.SecurityHomePath
}
func (info *Info_struct) SetSecurityHomePath(path string) {
	info.security.SecurityHomePath = path
}

func (info *Info_struct) ValidatorServiceUrl() string {
	if info.security.Validator_service_url != "" {
		return info.security.Validator_service_url
	}
	return ValidatorDefaultEndpoint
}
func (info *Info_struct) SetValidatorServiceUrl(path string) {
	info.security.Validator_service_url = path
}

func (info *Info_struct) SecurityMode() string {
	return info.security.Mode
}
func (info *Info_struct) IsIastMode() bool {
	return secUtils.CaseInsensitiveEquals(info.security.Mode, "IAST")
}

func (info *Info_struct) BodyLimit() int {
	return info.security.Request.BodyLimit * 1000
}

func (info *Info_struct) SetBodyLimit(bodyLimit int) {
	info.security.Request.BodyLimit = bodyLimit
}

func (info *Info_struct) ScanControllersIastLoadInterval() int {
	return info.security.ScanControllers.IastScanRequestRateLimit
}

func (info *Info_struct) SetscanControllersIastLoadInterval(iastLoadInterval int) {
	info.security.ScanControllers.IastScanRequestRateLimit = iastLoadInterval
}

func (info *Info_struct) ScanInstanceCount() int {
	return info.security.ScanControllers.ScanInstanceCount
}
func (info *Info_struct) SetScanInstanceCount(scanInstanceCount int) {
	info.security.ScanControllers.ScanInstanceCount = scanInstanceCount
}

func (info *Info_struct) GetApiData() []any {
	urlmappings := []any{}

	if info.ApiData != nil {
		info.ApiData.Range(func(key, value interface{}) bool {
			urlmappings = append(urlmappings, value)
			return true
		})
	}

	return urlmappings
}

func (info *Info_struct) SetApiData(data Urlmappings) {
	key := data.Path + data.Method

	if info.ApiData == nil {
		info.ApiData = &sync.Map{}
	}
	if _, ok := info.ApiData.Load(key); !ok {
		info.ApiData.Store(key, data)
		return
	}
}

func (info *Info_struct) IastProbingInterval() int {
	info.ploicyMutex.Lock()
	defer info.ploicyMutex.Unlock()
	if GlobalInfo.currentPolicy.VulnerabilityScan.IastScan.Probing.Interval <= 0 {
		return 5
	} else {
		return GlobalInfo.currentPolicy.VulnerabilityScan.IastScan.Probing.Interval
	}
}

type metaData struct {
	linkingMetadata map[string]string
	accountID       string
	agentRunId      string
	entityGuid      string
	entityName      string
	sync.Mutex
}

func (m *metaData) GetEntityName() string {
	m.Lock()
	defer m.Unlock()
	return m.entityName
}

func (m *metaData) SetEntityName(value string) {
	m.Lock()
	defer m.Unlock()
	m.entityName = value
}

func (m *metaData) GetEntityGuid() string {
	m.Lock()
	defer m.Unlock()
	return m.entityGuid
}

func (m *metaData) SetEntityGuid(value string) {
	m.Lock()
	defer m.Unlock()
	m.entityGuid = value
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

func (m *metaData) GetLinkingMetadata() map[string]string {
	m.Lock()
	defer m.Unlock()
	return m.linkingMetadata
}

func (m *metaData) SetLinkingMetadata(value map[string]string) {
	m.Lock()
	defer m.Unlock()
	m.linkingMetadata = value
}

// EventData used to track number of request
type eventData struct {
	iastEventStats EventStats
	raspEventStats EventStats
	exitEventStats EventStats
	sync.Mutex
}

func (e *eventData) GetIastEventStats() *EventStats {
	if e == nil {
		return &EventStats{}
	}
	e.Lock()
	defer e.Unlock()
	return &e.iastEventStats
}
func (e *eventData) GetRaspEventStats() *EventStats {
	if e == nil {
		return &EventStats{}
	}
	e.Lock()
	defer e.Unlock()
	return &e.raspEventStats
}
func (e *eventData) GetExitEventStats() *EventStats {
	if e == nil {
		return &EventStats{}
	}
	e.Lock()
	defer e.Unlock()
	return &e.exitEventStats
}

func (e *eventData) ResetEventStats() {
	if e == nil {
		return
	}
	e.Lock()
	defer e.Unlock()

	e.iastEventStats = EventStats{}
	e.raspEventStats = EventStats{}
	e.exitEventStats = EventStats{}

}

type Urlmappings struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Handler string `json:"handler"`
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
	appName            string
	apiAccessorToken   string
	protectedServer    string
	appUUID            string
	sha256             string
	size               string
	contextPath        string
	pid                string
	Cmd                string
	cmdline            []string
	ports              []int
	ServerIp           string
	starttimestr       time.Time
	trafficStartedTime time.Time
	scanStartTime      time.Time
	binaryPath         string
	serverName         []string
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

func (r *runningApplicationInfo) GetStarttimestr() time.Time {
	return r.starttimestr
}

func (r *runningApplicationInfo) SetStarttimestr(value time.Time) {
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

func (r *runningApplicationInfo) GetTrafficStartedTime() int64 {

	if r.trafficStartedTime.IsZero() {
		return 0
	} else {
		return r.trafficStartedTime.Unix() * 1000
	}
}

func (r *runningApplicationInfo) SetTrafficStartedTime(value time.Time) {
	r.trafficStartedTime = value
}

func (r *runningApplicationInfo) GetScanStartTime() int64 {

	if r.trafficStartedTime.IsZero() {
		return 0
	} else {
		return r.scanStartTime.Unix() * 1000
	}
}

func (r *runningApplicationInfo) SetScanStartTime(value time.Time) {
	r.scanStartTime = value
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
	GlobalInfo.EventStats = EventStats{}
	GlobalInfo.InstrumentationData = Instrumentation{}
	GlobalInfo.EnvironmentInfo = EnvironmentInfo{}
	GlobalInfo.ApplicationInfo = runningApplicationInfo{}
	GlobalInfo.MetaData = metaData{}
	GlobalInfo.MetaData.linkingMetadata = map[string]string{}
	GlobalInfo.WebSocketConnectionStats = WebSocketConnectionStats{}

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
		if b, err := strconv.ParseBool(env); nil == err {
			return b
		}
	}
	return true
}

func init() {
	InitDefaultConfig()
	GlobalInfo.SetForceDisable(!isSecurityAgentEnabled())

}
