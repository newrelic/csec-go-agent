// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package newrelic_security_agent

import (
	"fmt"
	"path/filepath"

	"os"
	"runtime"
	"time"

	logging "github.com/newrelic/csec-go-agent/internal/security_logs"
	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

var logger logging.Logger

const (
	LOG_FILE        = "go-security-collector.log"
	INIT_LOG_FILE   = "go-security-collector-init.log"
	STATUS_LOG_FILE = "go-security-collector-status-%s.log"
	SECURITY_HOME   = "nr-security-home"
)

func checkDefaultConfig() {
	if secConfig.GlobalInfo.ValidatorServiceUrl() == "" {
		secConfig.GlobalInfo.SetValidatorServiceUrl("wss://csec.nr-data.net")
	}
	if secConfig.GlobalInfo.BodyLimit() == 0 {
		secConfig.GlobalInfo.SetBodyLimit(300)
	}

	if secConfig.GlobalInfo.ScanControllersIastLoadInterval() < 12 {
		secConfig.GlobalInfo.SetscanControllersIastLoadInterval(12)
	}
	if secConfig.GlobalInfo.ScanControllersIastLoadInterval() > 3600 {
		secConfig.GlobalInfo.SetscanControllersIastLoadInterval(3600)
	}

}

func initLogger(logFilePath string, isDebugLog bool) {
	logFilePath = filepath.Join(logFilePath, SECURITY_HOME, "logs")
	logLevel := "INFO"
	if isDebugLog {
		logLevel = "DEBUG"
	}
	err := logging.Init(LOG_FILE, INIT_LOG_FILE, logFilePath, os.Getpid())
	if err != nil {
		secIntercept.SendLogMessage(err.Error(), "logging", "SEVERE")
	}
	logging.SetLogLevel(logLevel)
	logger = logging.GetLogger("Init")
}

func initApplicationInfo(appName string) {
	secConfig.GlobalInfo.ApplicationInfo.SetAppName(appName)
	secConfig.GlobalInfo.ApplicationInfo.SetPid(secUtils.IntToString(os.Getpid()))
	binaryPath, err := os.Executable()
	if err != nil {
		binaryPath = os.Args[0]
	}
	secConfig.GlobalInfo.ApplicationInfo.SetBinaryPath(binaryPath)
	secConfig.GlobalInfo.ApplicationInfo.SetSha256(secUtils.CalculateSha256(binaryPath))
	secConfig.GlobalInfo.ApplicationInfo.SetCmd(os.Args[0])
	secConfig.GlobalInfo.ApplicationInfo.SetCmdline(os.Args[0:])
	secConfig.GlobalInfo.ApplicationInfo.SetStarttimestr(time.Now())
	secConfig.GlobalInfo.ApplicationInfo.SetSize(secUtils.CalculateFileSize(binaryPath))

	logger.Infoln("Security Agent is now INACTIVE for ", secConfig.GlobalInfo.ApplicationInfo.GetAppUUID())
	printlogs := fmt.Sprintf("go secure agent attached to process: PID = %s, with generated applicationUID = %s by STATIC attachment", secUtils.IntToString(os.Getpid()), secConfig.GlobalInfo.ApplicationInfo.GetAppUUID())
	logging.EndStage("2", "Generating unique identifier "+secConfig.GlobalInfo.ApplicationInfo.GetAppUUID())
	logging.PrintInitlog(printlogs)
}

func initEnvironmentInfo() {

	secConfig.GlobalInfo.EnvironmentInfo.CollectorIp = secUtils.FindIpAddress()
	secConfig.GlobalInfo.EnvironmentInfo.Wd = secUtils.GetCurrentWorkingDir()
	secConfig.GlobalInfo.EnvironmentInfo.Goos = runtime.GOOS
	secConfig.GlobalInfo.EnvironmentInfo.Goarch = runtime.GOARCH
	secConfig.GlobalInfo.EnvironmentInfo.Gopath = secUtils.GetGoPath()
	secConfig.GlobalInfo.EnvironmentInfo.Goroot = secUtils.GetGoRoot()

	env_type, cid, err := secUtils.GetContainerId()
	if err != nil {
		logger.Errorln(err)
	}
	if !env_type {
		secConfig.GlobalInfo.EnvironmentInfo.RunningEnv = "HOST"
	} else {
		secConfig.GlobalInfo.EnvironmentInfo.ContainerId = cid
		if secUtils.IsKubernetes() {
			secConfig.GlobalInfo.EnvironmentInfo.RunningEnv = "KUBERNETES"
			secConfig.GlobalInfo.EnvironmentInfo.Namespaces = secUtils.GetKubernetesNS()
			secConfig.GlobalInfo.EnvironmentInfo.PodId = secUtils.GetPodId()
		} else if secUtils.IsECS() {
			secConfig.GlobalInfo.EnvironmentInfo.RunningEnv = "ECS"
			secConfig.GlobalInfo.EnvironmentInfo.EcsTaskId = secUtils.GetEcsTaskId()
			err, ecsData := secUtils.GetECSInfo()
			if err == nil {
				secConfig.GlobalInfo.EnvironmentInfo.ImageId = ecsData.ImageID
				secConfig.GlobalInfo.EnvironmentInfo.Image = ecsData.Image
				secConfig.GlobalInfo.EnvironmentInfo.ContainerName = ecsData.Labels.ComAmazonawsEcsContainerName
				secConfig.GlobalInfo.EnvironmentInfo.EcsTaskDefinition = ecsData.Labels.ComAmazonawsEcsTaskDefinitionFamily + ":" + ecsData.Labels.ComAmazonawsEcsTaskDefinitionVersion
			} else {
				logger.Errorln(err)
			}
		} else {
			secConfig.GlobalInfo.EnvironmentInfo.RunningEnv = "CONTAINER"
		}
	}
}

func initSecurityAgent(applicationName, licenseKey string, isDebugLog bool, securityAgentConfig secConfig.Security) {
	if secConfig.GlobalInfo.IsForceDisable() {
		return
	}
	secConfig.GlobalInfo.ApplicationInfo.SetAppUUID(secUtils.GetUniqueUUID())
	secConfig.GlobalInfo.SetSecurity(securityAgentConfig)
	secConfig.GlobalInfo.ApplicationInfo.SetApiAccessorToken(licenseKey)
	secConfig.GlobalInfo.SetSecurityHomePath(secUtils.GetCurrentWorkingDir())
	checkDefaultConfig()
	initLogger(secConfig.GlobalInfo.SecurityHomePath(), isDebugLog)
	logging.EndStage("1", "Security agent is starting")
	initEnvironmentInfo()
	initApplicationInfo(applicationName)
	go secIntercept.InitLowSeverityEventScheduler()
	logger.Infoln("Security HOME:", secConfig.GlobalInfo.SecurityHomePath())
	logger.Infoln("Agent location ", secConfig.GlobalInfo.EnvironmentInfo.Gopath)
	logger.Infoln("Current working directory: ", filepath.Dir(secConfig.GlobalInfo.ApplicationInfo.GetBinaryPath()))

}
