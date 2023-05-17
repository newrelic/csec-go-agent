// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package security_event_generation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"errors"

	logging "github.com/newrelic/csec-go-agent/internal/security_logs"
	sysInfo "github.com/newrelic/csec-go-agent/internal/security_sysinfo"
	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
)

const (
	LOG_FILE             = "go-security-collector.log"
	INIT_LOG_FILE        = "go-security-collector-init.log"
	STATUS_LOG_FILE      = "go-security-collector-status-%s.log"
	SECURITY_HOME        = "nr-security-home"
	language             = "GOLANG"
	NR_CSEC_TRACING_DATA = "NR-CSEC-TRACING-DATA"
	maxSnapshotsFile     = 100
)

var (
	initlogs      = true
	firstEvent    = true
	HcBuffer      *secUtils.Cring
	logger        = logging.GetLogger("hook")
	removeChannel = make(chan string)
)

func InitHcScheduler() {
	logging.EndStage("5", "Security agent threads started")
	SendSecHealthCheck()
	t := time.NewTicker(5 * time.Minute)
	for {
		select {
		case <-t.C:
			SendSecHealthCheck()
		case <-removeChannel:
			return
		}
	}
}

func RemoveHcScheduler() {
	removeChannel <- "end"
}

func initHcBuffer() {
	hcBuffer := secUtils.NewCring(5)
	HcBuffer = &hcBuffer
}

func getApplicationIdentifiers(jsonName string) ApplicationIdentifiers {
	var applicationIdentifier ApplicationIdentifiers
	applicationIdentifier.CollectorVersion = secUtils.CollectorVersion
	applicationIdentifier.JSONName = jsonName
	applicationIdentifier.JSONVersion = secUtils.JsonVersion
	applicationIdentifier.CollectorType = secUtils.CollectorType
	applicationIdentifier.Language = language
	applicationIdentifier.BuildNumber = secUtils.BuildNumber
	applicationIdentifier.Framework = ""
	applicationIdentifier.GroupName = secConfig.GlobalInfo.Security.Mode
	applicationIdentifier.ApplicationUUID = secConfig.GlobalInfo.ApplicationInfo.AppUUID
	applicationIdentifier.NodeID = secConfig.GlobalInfo.EnvironmentInfo.NodeId
	applicationIdentifier.PolicyVersion = secConfig.GlobalInfo.CurrentPolicy.Version
	applicationIdentifier.Pid = secConfig.GlobalInfo.ApplicationInfo.Pid
	applicationIdentifier.StartTime = secConfig.GlobalInfo.ApplicationInfo.Starttimestr
	applicationIdentifier.LinkingMetadata = secConfig.GlobalInfo.LinkingMetadata
	return applicationIdentifier

}

func SendSecHealthCheck() {
	if HcBuffer == nil {
		initHcBuffer()
	}
	var hc healthcheck
	hc.EventType = "sec_health_check_lc"
	hc.ApplicationIdentifiers = getApplicationIdentifiers("LAhealthcheck")
	hc.ProtectedServer = secConfig.GlobalInfo.ApplicationInfo.ProtectedServer
	hc.EventDropCount = secConfig.GlobalInfo.EventData.EventDropCount
	hc.EventProcessed = secConfig.GlobalInfo.EventData.EventProcessed
	hc.EventSentCount = secConfig.GlobalInfo.EventData.EventSentCount
	hc.HTTPRequestCount = secConfig.GlobalInfo.EventData.HTTPRequestCount
	stats := sysInfo.GetStats(secConfig.GlobalInfo.ApplicationInfo.Pid, secConfig.GlobalInfo.ApplicationInfo.BinaryPath)
	hc.Stats = stats
	serviceStatus := getServiceStatus()
	hc.ServiceStatus = serviceStatus

	healthCheck, _ := sendEvent(hc)
	HcBuffer.ForceInsert(healthCheck)
	populateStatusLogs(serviceStatus, stats)

	secConfig.GlobalInfo.EventData.EventDropCount = 0
	secConfig.GlobalInfo.EventData.EventProcessed = 0
	secConfig.GlobalInfo.EventData.EventSentCount = 0
	secConfig.GlobalInfo.EventData.HTTPRequestCount = 0
}

func SendApplicationInfo() {
	if secConfig.GlobalInfo.IsForceDisable {
		return
	}
	var appInfo applicationInfo
	appInfo.ApplicationIdentifiers = getApplicationIdentifiers("applicationinfo")
	hostname, _ := os.Hostname()

	eventInfo := map[string]interface{}{
		"name":              hostname,
		"creationTimestamp": time.Now().Unix() * 1000,
		"ipAddress":         secConfig.GlobalInfo.EnvironmentInfo.CollectorIp,
	}

	identifier := map[string]interface{}{
		"nodeName":    secConfig.GlobalInfo.EnvironmentInfo.NodeName,
		"nodeId":      secConfig.GlobalInfo.EnvironmentInfo.NodeId,
		"nodeIp":      secConfig.GlobalInfo.EnvironmentInfo.NodeIp,
		"collectorIp": secConfig.GlobalInfo.EnvironmentInfo.CollectorIp,
		"eventInfo":   eventInfo,
	}

	envInfo := map[string]interface{}{}

	if secConfig.GlobalInfo.EnvironmentInfo.RunningEnv == "HOST" {
		identifier["kind"] = "HOST"
		identifier["id"] = secConfig.GlobalInfo.EnvironmentInfo.NodeId
		envInfo["id"] = secConfig.GlobalInfo.EnvironmentInfo.NodeId
		envInfo["os"] = secConfig.GlobalInfo.EnvironmentInfo.Goos
		envInfo["arch"] = secConfig.GlobalInfo.EnvironmentInfo.Goarch
		envInfo["ipAddress"] = secConfig.GlobalInfo.EnvironmentInfo.CollectorIp
		secConfig.GlobalInfo.EnvironmentInfo.ID = secConfig.GlobalInfo.EnvironmentInfo.NodeId
	} else if secConfig.GlobalInfo.EnvironmentInfo.RunningEnv == "CONTAINER" {
		identifier["kind"] = "CONTAINER"
		identifier["id"] = secConfig.GlobalInfo.EnvironmentInfo.ContainerId
		envInfo["id"] = secConfig.GlobalInfo.EnvironmentInfo.ContainerId
		envInfo["ipAddress"] = secConfig.GlobalInfo.EnvironmentInfo.CollectorIp
		secConfig.GlobalInfo.EnvironmentInfo.ID = secConfig.GlobalInfo.EnvironmentInfo.ContainerId
	} else if secConfig.GlobalInfo.EnvironmentInfo.RunningEnv == "KUBERNETES" {
		identifier["kind"] = "POD"
		identifier["id"] = secConfig.GlobalInfo.EnvironmentInfo.PodId
		envInfo["id"] = secConfig.GlobalInfo.EnvironmentInfo.PodId
		envInfo["ipAddress"] = secConfig.GlobalInfo.EnvironmentInfo.CollectorIp
		envInfo["namespace"] = secConfig.GlobalInfo.EnvironmentInfo.Namespaces
		secConfig.GlobalInfo.EnvironmentInfo.ID = secConfig.GlobalInfo.EnvironmentInfo.PodId
	} else if secConfig.GlobalInfo.EnvironmentInfo.RunningEnv == "ECS" {
		identifier["kind"] = "ECS"
		identifier["id"] = secConfig.GlobalInfo.EnvironmentInfo.EcsTaskId
		envInfo["id"] = secConfig.GlobalInfo.EnvironmentInfo.EcsTaskId
		envInfo["ipAddress"] = secConfig.GlobalInfo.EnvironmentInfo.CollectorIp
		envInfo["imageId"] = secConfig.GlobalInfo.EnvironmentInfo.ImageId
		envInfo["imageName"] = secConfig.GlobalInfo.EnvironmentInfo.Image
		envInfo["ecsTaskDefinition"] = secConfig.GlobalInfo.EnvironmentInfo.EcsTaskDefinition
		envInfo["containerName"] = secConfig.GlobalInfo.EnvironmentInfo.ContainerName
	}
	identifier["envInfo"] = envInfo
	appInfo.Identifier = identifier
	// configer deployedApplications and serverInfo

	bin := filepath.Base(secConfig.GlobalInfo.ApplicationInfo.Cmd)

	if secConfig.GlobalInfo.ApplicationInfo.Ports != nil && len(secConfig.GlobalInfo.ApplicationInfo.Ports) > 0 {
		secConfig.GlobalInfo.ApplicationInfo.ContextPath = bin + ":" + strconv.Itoa(secConfig.GlobalInfo.ApplicationInfo.Ports[0]) + "/"
	} else {
		secConfig.GlobalInfo.ApplicationInfo.ContextPath = bin
	}
	applicationPort := secConfig.GlobalInfo.ApplicationInfo.Ports
	if applicationPort == nil {
		applicationPort = make([]int, 0)
		applicationPort = append(applicationPort, -1)
	}
	deployedApplications := map[string]interface{}{
		"deployedPath": secConfig.GlobalInfo.ApplicationInfo.BinaryPath,
		"appName":      bin,
		"sha256":       secConfig.GlobalInfo.ApplicationInfo.Sha256,
		"size":         secConfig.GlobalInfo.ApplicationInfo.Size,
		"contextPath":  secConfig.GlobalInfo.ApplicationInfo.ContextPath,
		"isEmbedded":   false,
		"ports":        applicationPort,
	}

	var arg11 []interface{}
	arg11 = append(arg11, deployedApplications)

	serverName := strings.Join(secConfig.GlobalInfo.ApplicationInfo.ServerName, ",")
	serverInfo := map[string]interface{}{
		"name":                 serverName,
		"deployedApplications": arg11,
	}

	appInfo.ServerInfo = serverInfo
	appInfo.JSONName = "applicationinfo"
	appInfo.JSONVersion = secUtils.JsonVersion
	appInfo.Sha256 = secConfig.GlobalInfo.ApplicationInfo.Sha256
	appInfo.Pid = secConfig.GlobalInfo.ApplicationInfo.Pid

	appInfo.Cmdline = secConfig.GlobalInfo.ApplicationInfo.Cmdline
	appInfo.RunCommand = strings.Join(secConfig.GlobalInfo.ApplicationInfo.Cmdline, " ")
	appInfo.UserDir = secConfig.GlobalInfo.EnvironmentInfo.Wd
	appInfo.BinaryName = bin
	appInfo.OsArch = secConfig.GlobalInfo.EnvironmentInfo.Goarch
	appInfo.OsName = secConfig.GlobalInfo.EnvironmentInfo.Goos
	appInfo.BinaryPath = secConfig.GlobalInfo.ApplicationInfo.BinaryPath
	appInfo.AgentAttachmentType = "STATIC"

	app, err := sendEvent(appInfo)
	if err != nil && initlogs {
		logging.PrintInitErrolog("Error while Sending ApplicationInfo " + err.Error())
		return
	}
	if initlogs {
		logging.EndStage("3", "Gathering information about the application")
		logging.PrintInitlog("Application info generated  " + app)
		initlogs = false
	}

}

func SendFuzzFailEvent(fuzzHeader string) {
	var fuzzFailEvent FuzzFailBean
	fuzzFailEvent.FuzzHeader = fuzzHeader
	fuzzFailEvent.ApplicationIdentifiers = getApplicationIdentifiers("fuzzfail")
	_, err := sendEvent(fuzzFailEvent)
	if err != nil {
		logger.Errorln(err)
	}
}

func SendVulnerableEvent(req *secUtils.Info_req, category string, args interface{}, vulnerabilityDetails secUtils.VulnerabilityDetails, eventId string) *secUtils.EventTracker {
	var tmp_event eventJson

	eventCategory := category
	if eventCategory == "SQL_DB_COMMAND" {
		eventCategory = "SQLITE"
	} else if category == "NOSQL_DB_COMMAND" {
		eventCategory = "MONGO"
	}

	tmp_event.ID = eventId
	tmp_event.CaseType = category
	tmp_event.EventCategory = eventCategory
	tmp_event.Parameters = args
	tmp_event.EventGenerationTime = strconv.FormatInt(time.Now().Unix()*1000, 10)
	tmp_event.BlockingProcessingTime = "1"
	tmp_event.HTTPRequest = req.Request
	tmp_event.VulnerabilityDetails = vulnerabilityDetails
	tmp_event.ApplicationIdentifiers = getApplicationIdentifiers("Event")

	fuzzHeader := (*req).RequestIdentifier
	// if (*req).RequestIdentifier != "" {
	// 	tmp_event.Stacktrace = []string{}
	// }

	if secConfig.GlobalInfo.CurrentPolicy.VulnerabilityScan.Enabled && secConfig.GlobalInfo.CurrentPolicy.VulnerabilityScan.IastScan.Enabled {
		if fuzzHeader != "" {
			tmp_event.IsIASTRequest = true
		}
		tmp_event.IsIASTEnable = true
	}

	if tmp_event.HTTPRequest.IsGRPC {
		body := (*req).GrpcBody
		grpc_bodyJson, err1 := json.Marshal(body)
		if err1 != nil {
			logger.Errorln("grpc_body JSON invalid" + string(grpc_bodyJson))
			return nil
		} else {
			tmp_event.HTTPRequest.Body = string(grpc_bodyJson)
		}
	}

	event_json, err1 := sendEvent(tmp_event)
	if err1 != nil {
		logger.Errorln("JSON invalid" + string(event_json))
		return nil
	}

	if firstEvent {
		logging.EndStage("8", "First event sent for validation. Security agent started successfully.")
		logging.PrintInitlog("First event processed : " + string(event_json))
		firstEvent = false
		logging.Disableinitlogs()
	}
	tracingHeader := tmp_event.HTTPRequest.Headers[NR_CSEC_TRACING_DATA]
	return &secUtils.EventTracker{APIID: tmp_event.APIID, ID: tmp_event.ID, CaseType: tmp_event.CaseType, TracingHeader: tracingHeader, RequestIdentifier: fuzzHeader}

}

func SendExitEvent(eventTracker *secUtils.EventTracker, requestIdentifier string) {

	var tmp_event Exitevent
	tmp_event.ApplicationIdentifiers = getApplicationIdentifiers("exit-event")
	tmp_event.RequestIdentifier = eventTracker.RequestIdentifier
	tmp_event.CaseType = eventTracker.CaseType
	tmp_event.ExecutionId = eventTracker.ID
	_, err := sendEvent(tmp_event)
	if err != nil {
		logger.Errorln(err)
	}
}

func SendUpdatedPolicy(policy secConfig.Policy) {
	logger.Infoln("Sending Updated policy ", policy.Version)
	type policy1 struct {
		JSONName string `json:"jsonName"`
		secConfig.Policy
	}

	_, err := sendEvent(policy1{"lc-policy", policy})
	if err != nil {
		logger.Errorln(err)
	}
}

func sendEvent(event interface{}) (string, error) {
	event_json, err := json.Marshal(event)
	if err != nil {
		logger.Errorln("Marshal JSON before send", err)
		return "", err
	}
	logger.Debugln("ready to send : ", string(event_json))
	if secConfig.SecureWS != nil {
		(secConfig.SecureWS).RegisterEvent([]byte(string(event_json)))
		return string(event_json), nil
	} else {
		logger.Errorln("websocket not configured to send event")
		return string(event_json), errors.New("websocket not configured to send event")
	}
}

func getServiceStatus() map[string]interface{} {
	ServiceStatus := map[string]interface{}{}
	ServiceStatus["websocket"] = wsStatus()
	ServiceStatus["agentActiveStat"] = isAgentActiveState()
	ServiceStatus["logWriter"] = isLogAccessible(filepath.Join(secConfig.GlobalInfo.Security.SecurityHomePath, "nr-security-home", "logs", LOG_FILE))
	ServiceStatus["initLogWriter"] = isLogAccessible(filepath.Join(secConfig.GlobalInfo.Security.SecurityHomePath, "nr-security-home", "logs", INIT_LOG_FILE))
	ServiceStatus["statusLogWriter"] = isLogAccessible(filepath.Join(secConfig.GlobalInfo.Security.SecurityHomePath, "nr-security-home", "logs", "snapshots", fmt.Sprintf(STATUS_LOG_FILE, secConfig.GlobalInfo.ApplicationInfo.AppUUID)))
	ServiceStatus["iastRestClient"] = iastRestClientStatus()
	return ServiceStatus

}
