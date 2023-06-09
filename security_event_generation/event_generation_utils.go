// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

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
	"\nLast 5 Health Checks are:\n\n %s"

type eventJson struct {
	ApplicationIdentifiers
	Parameters             interface{}          `json:"parameters"`
	EventGenerationTime    string               `json:"eventGenerationTime"`
	HTTPRequest            secUtils.RequestInfo `json:"httpRequest"`
	ID                     string               `json:"id"`
	CaseType               string               `json:"caseType"`
	EventCategory          string               `json:"eventCategory"`
	MetaData               metaData             `json:"metaData"`
	BlockingProcessingTime string               `json:"blockingProcessingTime"`
	IsAPIBlocked           bool                 `json:"isAPIBlocked"`
	IsIASTEnable           bool                 `json:"isIASTEnable"`
	IsIASTRequest          bool                 `json:"isIASTRequest"`
	secUtils.VulnerabilityDetails
}

type metaData struct {
	TriggerViaRCI             bool `json:"triggerViaRCI"`
	TriggerViaDeserialisation bool `json:"triggerViaDeserialisation"`
	TriggerViaXXE             bool `json:"triggerViaXXE"`
	IsClientDetectedFromXFF   bool `json:"isClientDetectedFromXFF"`
	APIBlocked                bool `json:"apiBlocked"`
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
	EventType        string      `json:"eventType"`
	ProtectedServer  string      `json:"protectedServer"`
	EventDropCount   uint64      `json:"eventDropCount"`
	EventProcessed   uint64      `json:"eventProcessed"`
	EventSentCount   uint64      `json:"eventSentCount"`
	HTTPRequestCount uint64      `json:"httpRequestCount"`
	Stats            interface{} `json:"stats"`
	ServiceStatus    interface{} `json:"serviceStatus"`
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
	RequestIdentifier string `json:"RequestIdentifier"`
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
	LinkingMetadata  interface{} `json:"linkingMetadata"`
}

type FuzzFailBean struct {
	ApplicationIdentifiers
	FuzzHeader string `json:"fuzzHeader"`
}

//status utils function
/////

func populateStatusLogs(service, process map[string]interface{}) {

	status := fmt.Sprintf(statusTemplate,
		time.Now(),
		secConfig.GlobalInfo.ApplicationInfo.Starttimestr,
		secConfig.GlobalInfo.ApplicationInfo.AppUUID,
		secConfig.GlobalInfo.Security.SecurityHomePath,
		secConfig.GlobalInfo.EnvironmentInfo.Gopath,
		runtime.Version(),
		secConfig.GlobalInfo.ApplicationInfo.Pid,
		"Go",
		os.Args[0],
		filepath.Dir(secConfig.GlobalInfo.ApplicationInfo.BinaryPath),
		secUtils.GetCurrentWorkingDir(),
		secConfig.GlobalInfo.Security.Mode,
		secConfig.GlobalInfo.ApplicationInfo.ServerName,
		"",
		secConfig.GlobalInfo.Security.Validator_service_url,
		wsStatus(),
		secConfig.GlobalInfo.CurrentPolicy.Version,
		secUtils.MapToString(process),
		secUtils.MapToString(service),
		logging.GetErrorLogs(),
		HcBuffer.Get())
	statusFilePath := filepath.Join(secConfig.GlobalInfo.Security.SecurityHomePath, "nr-security-home", "logs", "snapshots")
	err := os.MkdirAll(statusFilePath, os.ModePerm)
	if err != nil {
		logger.Errorln(err)
	}
	err = os.Chmod(statusFilePath, 0777)
	if err != nil {
		logger.Errorln(err)
	}
	statusFilePath1 := filepath.Join(statusFilePath, fmt.Sprintf("go-security-collector-status-%s.log", secConfig.GlobalInfo.ApplicationInfo.AppUUID))
	f, err := os.OpenFile(statusFilePath1, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		logger.Errorln(err)
	}
	defer f.Close()
	_, err2 := f.WriteString(status)
	if err2 != nil {
		logger.Errorln(err2)
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
	file, err := os.OpenFile(fileName, os.O_WRONLY, 0777)
	if err == nil {
		defer file.Close()
		return "OK"
	} else {
		return "ERROR"
	}
}

func isAgentActiveState() string {
	if secConfig.GlobalInfo != nil && secConfig.GlobalInfo.Security.Enabled {
		return "OK"
	} else {
		return "ERROR"
	}
}

func iastRestClientStatus() string {
	return "OK"
}
