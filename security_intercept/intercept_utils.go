// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_intercept

import (
	"bytes"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	logging "github.com/newrelic/csec-go-agent/internal/security_logs"
	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
)

func IsForceDisable() bool {
	return secConfig.GlobalInfo.IsForceDisable()
}

func IsDisable() bool {
	return !secConfig.GlobalInfo.IsSecurityEnabled()
}
func IsRXSSDisable() bool {
	return !secConfig.GlobalInfo.IsRxssEnabled()
}

func IsHooked() bool {
	if secConfig.GlobalInfo == nil {
		return false
	}
	return secConfig.GlobalInfo.InstrumentationData.Hooked
}
func SetHooked() {
	if secConfig.GlobalInfo == nil {
		return
	}
	secConfig.GlobalInfo.InstrumentationData.Hooked = true
}
func IsAgentInitializedForHook() bool {
	if secConfig.GlobalInfo == nil {
		logger.Debugln("secure_intercept - false - noInfo")
		return false
	}
	return true
}

func IsHookingoIsSupported() bool {
	return (runtime.GOOS == "linux" && runtime.GOARCH == "amd64")
}

func isAgentInitialized() bool {
	if secConfig.GlobalInfo == nil && secConfig.Secure == nil && !secConfig.GlobalInfo.InstrumentationData.Hooked {
		logger.Debugln("Secure agent is not initilized")
		return false
	}
	return true
}

func getServerPort() string {
	serverPort := secConfig.GlobalInfo.ApplicationInfo.GetPorts()
	if serverPort != nil && len(serverPort) > 0 {
		return strconv.Itoa(serverPort[0])
	}
	return ""
}

func IsFileExist(name string) bool {
	return secUtils.IsFileExist(name)
}

func IsHookedLog(name string, e error) {
	logging.IsHooked(name, e)
}

func GetLogger(loggerName string) logging.Logger {
	return logging.GetLogger(loggerName)
}

/**
 * Utiltity to check file integrity
 */

func isFileModified(flag int) bool {
	return ((flag & syscall.O_RDWR) | (flag & syscall.O_WRONLY) | (flag & syscall.O_CREAT) | (flag & syscall.O_APPEND)) != 0
}

// fileInApp used to check given file path belongs to application path or not
func fileInApplicationPath(fn string) bool {

	applicationPath := secConfig.GlobalInfo.EnvironmentInfo.Wd

	// check file absolute file path
	absoluteFileName, err := filepath.Abs(fn)
	logger.Debugln("fileInApp: absoluteFileName", absoluteFileName, fn)
	if err == nil && strings.HasPrefix(absoluteFileName, applicationPath) {
		return true
	}

	// check file Symlink belongs to application path or not
	w2, err := os.Lstat(fn)
	if err == nil && w2.Mode()&os.ModeSymlink != 0 {
		linkedFileName, err := os.Readlink(fn)
		logger.Debugln("fileInApp: linkedFileName", linkedFileName, fn)
		if err == nil && strings.HasPrefix(linkedFileName, applicationPath) {
			return true
		}
	}
	return false
}

// fileExecByExtension is used to check opened file is executable file or not
// example :  exec(go build downloaded.go) exec ./downloaded

func fileExecByExtension(fn string) bool {

	s := []string{".jar", ".py", ".sh", ".ksh", ".rb", ".php", ".py",
		".js", ".so", ".go"}

	for _, v := range s {
		if strings.HasSuffix(fn, strings.ToLower(v)) {
			return true
		}
	}
	return false
}

// // fileExecByExtension is used to check opened file is elf binary or not
// func fileIsBinaryExec(fn string) bool {
// 	f, err := os.Open(fn)
// 	if err != nil {
// 		return false
// 	}
// 	_, err = elf.NewFile(f)
// 	f.Close()
// 	return err == nil
// }

func getContentType(header map[string]string) string {

	for key, v := range header {
		if secUtils.CaseInsensitiveEquals(key, "Content-type") {
			return v
		}
	}
	return ""
}

func getIpAndPort(data string) (string, string) {
	var port = ""
	var ip = ""
	if data == "" {
		return ip, port
	}

	index := strings.LastIndex(data, ":")
	if index < 0 {
		return ip, port
	}
	port = data[index+1:]
	tmpIp := data[:index]
	index = strings.Index(tmpIp, ":")
	if index < 0 {
		return tmpIp, port
	}
	tmpIp = tmpIp[1 : len(tmpIp)-1]
	index = strings.Index(tmpIp, "%")
	//fmt.Println(index)
	if index < 0 {
		return tmpIp, port
	}
	tmpIp = tmpIp[:index]
	return tmpIp, port
}

type webRequest interface {
	GetHeader() http.Header
	GetURL() *url.URL
	GetMethod() string
	GetTransport() string
	GetHost() string
	GetBody() *bytes.Buffer
	GetServerName() string
	Type1() string
	GetRemoteAddress() string
}

type parameters struct {
	Payload     interface{} `json:"payload"`
	PayloadType interface{} `json:"payloadType"`
}
