// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package security_event_generation

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	logging "github.com/newrelic/csec-go-agent/internal/security_logs"
	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
)

const statusTemplate = "Snapshot timestamp: : %s \n" +
	"Go Agent start timestamp: %s with application uuid:%s \n" +
	"Security HOME: %s \n" +
	"Agent location %s \n" +
	"Using agent for Go version:%s, PID:%s \n" +
	"Process title: %s \n" +
	"Process binary: %s\n" +
	"Application location%s\n" +
	"Current working directory: %s\n" +
	"Agent mode: %s\n" +
	"Application server: %s\n" +
	"Application Framework: %s\n" +
	"Websocket connection to Prevent Web: %s, Status: %s\n" +
	"Instrumentation successful\n" +
	"Tracking loaded modules in the application\n" +
	"Policy applied successfully. Policy version is: %s\n" +
	"Started Health Check for Agent\n" +
	"Started Inbound and Outbound monitoring \n" +
	"\nProcess stats:\n\n%s\n" +
	"\nService stats:\n\n%s\n" +
	"\nLast 5 errors: \n%s\n" +
	"\nLast 5 Health Checks are:\n\n"

type eventJson struct {
	ApplicationIdentifiers
	Parameters             interface{}           `json:"parameters"`
	EventGenerationTime    string                `json:"eventGenerationTime"`
	HTTPRequest            secUtils.RequestInfo  `json:"httpRequest"`
	HTTPResponse           secUtils.ResponseInfo `json:"httpResponse"`
	ID                     string                `json:"id"`
	CaseType               string                `json:"caseType"`
	EventCategory          string                `json:"eventCategory"`
	MetaData               metaData              `json:"metaData"`
	BlockingProcessingTime string                `json:"blockingProcessingTime"`
	IsAPIBlocked           bool                  `json:"isAPIBlocked"`
	IsIASTEnable           bool                  `json:"isIASTEnable"`
	ParentId               string                `json:"parentId"`
	IsIASTRequest          bool                  `json:"isIASTRequest"`
	secUtils.VulnerabilityDetails
}

type metaData struct {
	TriggerViaRCI             bool        `json:"triggerViaRCI"`
	TriggerViaDeserialisation bool        `json:"triggerViaDeserialisation"`
	TriggerViaXXE             bool        `json:"triggerViaXXE"`
	IsClientDetectedFromXFF   bool        `json:"isClientDetectedFromXFF"`
	APIBlocked                bool        `json:"apiBlocked"`
	ReflectedMetaData         interface{} `json:"reflectedMetaData"`
	AppServerInfo             struct {
		ApplicationDirectory string `json:"applicationDirectory"`
		ServerBaseDirectory  string `json:"serverBaseDirectory"`
	} `json:"appServerInfo"`
}

// ---------------------------------------------------
// 					Appliation info
// ---------------------------------------------------

type applicationInfo struct {
	ApplicationIdentifiers
	JSONName                    string                      `json:"jsonName"`
	JSONVersion                 string                      `json:"jsonVersion"`
	Sha256                      string                      `json:"sha256"`
	Pid                         string                      `json:"pid"`
	Cmdline                     []string                    `json:"cmdline"`
	RunCommand                  string                      `json:"runCommand"`
	UserDir                     string                      `json:"userDir"`
	ServerInfo                  map[string]interface{}      `json:"serverInfo"`
	BootLibraryPath             string                      `json:"bootLibraryPath"`
	BinaryName                  string                      `json:"binaryName"`
	BinaryVersion               string                      `json:"binaryVersion"`
	OsArch                      string                      `json:"osArch"`
	OsName                      string                      `json:"osName"`
	OsVersion                   string                      `json:"osVersion"`
	BinaryPath                  string                      `json:"binaryPath"`
	AgentAttachmentType         string                      `json:"agentAttachmentType"`
	Identifier                  map[string]interface{}      `json:"identifier"`
	UserProvidedApplicationInfo userProvidedApplicationInfo `json:"userProvidedApplicationInfo"`
}

type userProvidedApplicationInfo struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Tags    []string `json:"tags"`
}

// ---------------------------------------------------
// 					LAhealthcheck
// ---------------------------------------------------

type healthcheck struct {
	ApplicationIdentifiers
	EventType                string                             `json:"eventType"`
	ProtectedServer          string                             `json:"protectedServer"`
	Stats                    interface{}                        `json:"stats"`
	ServiceStatus            interface{}                        `json:"serviceStatus"`
	WebSocketConnectionStats secConfig.WebSocketConnectionStats `json:"webSocketConnectionStats"`
	IastReplayRequest        secConfig.IastReplayRequest        `json:"iastReplayRequest"`
	EventStats               secConfig.EventStats               `json:"eventStats"`
	ProcStartTime            int64                              `json:"procStartTime"`
	TrafficStartedTime       int64                              `json:"trafficStartedTime"`
	ScanStartTime            int64                              `json:"scanStartTime"`
}

type ThreadPoolStats struct {
	FuzzRequestCount     uint64 `json:"fuzzRequestCount"`
	FuzzRequestQueueSize int    `json:"fuzzRequestQueueSize"`
	EventSendQueueSize   int    `json:"eventSendQueueSize"`
}

type SourceID struct {
	ApplicationUUID string `json:"applicationUUID"`
	ContextPath     string `json:"contextPath"`
	ServerPort      string `json:"serverPort"`
	Target          string `json:"target"`
}

type Grpcbody struct {
	Body []interface{} `json:"body"`
}

type Exitevent struct {
	ApplicationIdentifiers
	ExecutionId       string `json:"executionId"`
	CaseType          string `json:"caseType"`
	RequestIdentifier string `json:"k2RequestIdentifier"`
}

type ApplicationIdentifiers struct {
	ApplicationUUID  string      `json:"applicationUUID"`
	CollectorVersion string      `json:"collectorVersion"`
	GroupName        string      `json:"groupName"`
	BuildNumber      string      `json:"buildNumber"`
	NodeID           string      `json:"nodeId"`
	CollectorType    string      `json:"collectorType"`
	PolicyVersion    string      `json:"policyVersion"`
	Language         string      `json:"language"`
	Framework        string      `json:"framework"`
	JSONVersion      string      `json:"jsonVersion"`
	JSONName         string      `json:"jsonName"`
	Pid              string      `json:"pid"`
	StartTime        string      `json:"startTime"`
	AppAccountId     string      `json:"appAccountId"`
	AppEntityGuid    string      `json:"appEntityGuid"`
	LinkingMetadata  interface{} `json:"linkingMetadata"`
}

type FuzzFailBean struct {
	ApplicationIdentifiers
	FuzzHeader string `json:"fuzzHeader"`
}

type IASTDataRequestBeen struct {
	ApplicationIdentifiers
	BatchSize         int         `json:"batchSize"`
	CompletedRequests interface{} `json:"completedRequests"`
	PendingRequestIds []string    `json:"pendingRequestIds"`
}

type UrlMappingBeen struct {
	ApplicationIdentifiers
	EventType string      `json:"eventType"`
	Mappings  interface{} `json:"mappings"`
}

type Urlmappings struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Handler string `json:"handler"`
}

type LogMessage struct {
	ApplicationIdentifiers
	Timestamp  int64     `json:"timestamp"`
	Level      string    `json:"level"`
	Message    string    `json:"message"`
	Caller     string    `json:"caller"`
	Exception  Exception `json:"exception"`
	ThreadName string    `json:"threadName"`
}

type Exception struct {
	Message    string      `json:"message"`
	Cause      interface{} `json:"cause"`
	StackTrace []string    `json:"stackTrace"`
}

type Panic struct {
	Message    any         `json:"message"`
	Cause      interface{} `json:"cause"`
	Type       string      `json:"type"`
	Stacktrace []string    `json:"stackTrace"`
}

type PanicReport struct {
	ApplicationIdentifiers
	HTTPRequest  secUtils.RequestInfo `json:"httpRequest"`
	Counter      int                  `json:"counter"`
	ResponseCode int                  `json:"responseCode"`
	Category     string               `json:"category"`
	Exception    any                  `json:"exception"`
	TraceId      string               `json:"traceId"`
}

//status utils function
/////

func populateStatusLogs(service, process map[string]interface{}) {
	bufferError := ""
	for _, err := range logging.GetErrorLogs() {
		if err != nil {
			bufferError = bufferError + fmt.Sprintf("%s", err)
		}
	}
	status := fmt.Sprintf(statusTemplate,
		time.Now(),
		secConfig.GlobalInfo.ApplicationInfo.GetStarttimestr(),
		secConfig.GlobalInfo.ApplicationInfo.GetAppUUID(),
		secConfig.GlobalInfo.SecurityHomePath(),
		secConfig.GlobalInfo.EnvironmentInfo.Gopath,
		runtime.Version(),
		secConfig.GlobalInfo.ApplicationInfo.GetPid(),
		"Go",
		os.Args[0],
		filepath.Dir(secConfig.GlobalInfo.ApplicationInfo.GetBinaryPath()),
		secUtils.GetCurrentWorkingDir(),
		secConfig.GlobalInfo.SecurityMode(),
		secConfig.GlobalInfo.ApplicationInfo.GetServerName(),
		"",
		secConfig.GlobalInfo.ValidatorServiceUrl(),
		wsStatus(),
		secConfig.GlobalInfo.GetCurrentPolicy().Version,
		secUtils.MapToString(process),
		secUtils.MapToString(service),
		bufferError)

	bufferHc := HcBuffer.Get()
	for _, hc := range bufferHc {
		if hc != nil {
			status = status + fmt.Sprintf("%s\n", hc)
		}
	}

	statusFilePath := filepath.Join(secConfig.GlobalInfo.SecurityHomePath(), "nr-security-home", "logs", "snapshots")
	err := os.MkdirAll(statusFilePath, os.ModePerm)
	if err != nil {
		SendLogMessage(err.Error(), "populateStatusLogs", "SEVERE")
		logger.Errorln(err)
		return
	}
	err = os.Chmod(statusFilePath, 0770)
	if err != nil {
		SendLogMessage(err.Error(), "populateStatusLogs", "SEVERE")
		logger.Errorln(err)
		return
	}
	statusFilePath1 := filepath.Join(statusFilePath, fmt.Sprintf("go-security-collector-status-%s.log", secConfig.GlobalInfo.ApplicationInfo.GetAppUUID()))
	f, err := os.OpenFile(statusFilePath1, os.O_RDWR|os.O_CREATE, 0660)
	f.Chmod(0660)
	if err != nil {
		SendLogMessage(err.Error(), "populateStatusLogs", "SEVERE")
		logger.Errorln(err)
		return
	}
	defer f.Close()
	_, err2 := f.WriteString(status)
	if err2 != nil {
		logger.Errorln(err2)
		return
	}
	removeOlderSnapshots(statusFilePath, "go-security-collector-status")
}

func removeOlderSnapshots(dirpath, filename string) {
	files, err := ioutil.ReadDir(dirpath)
	if err != nil {
		logger.Errorln(err.Error())
		return
	}
	var dir = []os.FileInfo{}
	for _, file := range files {
		if strings.Contains(file.Name(), filename) {
			dir = append(dir, file)
		}
	}
	if len(dir) < maxSnapshotsFile {
		return
	}
	sort.Slice(dir, func(i, j int) bool {
		return dir[i].ModTime().Before(dir[j].ModTime())
	})
	err = os.Remove(filepath.Join(dirpath, dir[0].Name()))
	if err != nil {
		logger.Errorln(err.Error())
		return
	}
}

func wsStatus() string {
	if secConfig.GlobalInfo != nil && secConfig.SecureWS != nil && secConfig.SecureWS.GetStatus() {
		return "OK"
	} else {
		return "ERROR"
	}
}

func isLogAccessible(fileName string) string {
	file, err := os.OpenFile(fileName, os.O_WRONLY, 0660)
	if err == nil {
		defer file.Close()
		return "OK"
	} else {
		return "ERROR"
	}
}

func isAgentActiveState() string {
	if secConfig.GlobalInfo != nil && secConfig.GlobalInfo.IsSecurityEnabled() {
		return "OK"
	} else {
		return "ERROR"
	}
}

func iastRestClientStatus() string {
	return "OK"
}
