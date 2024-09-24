// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package security_intercept

import (
	"fmt"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dlclark/regexp2"
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
func IsRxssDisabled() bool {
	return secConfig.GlobalInfo.IsRxssDisabled()
}

func RequestBodyReadLimit() int {
	return secConfig.GlobalInfo.BodyLimit()
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
	return "-1"
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

// fileAbs return the file absolute path without clean process
func fileAbs(path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return strings.Join([]string{wd, path}, string(os.PathSeparator)), nil
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

func recoverFromPanic(functionName string) {
	if r := recover(); r != nil {
		printlogs := fmt.Sprintf("Recovered from panic: %s", r)
		SendLogMessage(printlogs, functionName, "SEVERE")
	}
}

func getContentType(header map[string][]string) string {
	return getHeaderValue(header, "Content-type")
}

func getHeaderValue(header map[string][]string, key string) string {
	return textproto.MIMEHeader(header).Get(key)
}

func getIpAndPort(data string) (ip string, port string) {
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
	GetBody() []byte
	GetServerName() string
	Type1() string
	GetRemoteAddress() string
}

// merge webRequest and webRequestv2 in next major release (v1.0.0)
type webRequestv2 interface {
	webRequest
	IsDataTruncated() bool
}

func IsDataTruncated() bool {
	return false
}

type parameters struct {
	Payload     interface{} `json:"payload"`
	PayloadType interface{} `json:"payloadType"`
}

func parseFuzzRequestIdentifierHeader(requestHeaderVal string) (nrRequestIdentifier secUtils.NrRequestIdentifier) {
	nrRequestIdentifier.Raw = requestHeaderVal
	if secUtils.IsBlank(requestHeaderVal) {
		return
	}
	data := strings.Split(requestHeaderVal, IAST_SEP)

	if len(data) >= 6 {
		nrRequestIdentifier.APIRecordID = data[0]
		nrRequestIdentifier.RefID = data[1]
		nrRequestIdentifier.RefValue = data[2]
		nrRequestIdentifier.NextStage = data[3]
		nrRequestIdentifier.RecordIndex = data[4]
		nrRequestIdentifier.RefKey = data[5]
		nrRequestIdentifier.NrRequest = true

	}
	if len(data) >= 8 && !secUtils.IsAnyBlank(data[6], data[7]) {

		encryptedData := data[6]
		hashVerifier := data[7]
		logger.Debugln("Request Identifier, Encrypted Files = ", encryptedData)

		filesToCreate, err := secUtils.Decrypt(secConfig.GlobalInfo.MetaData.GetEntityGuid(), encryptedData, hashVerifier)

		if err != nil {
			logger.Errorln("Request Identifier, decryption of files failed ", err)
			SendLogMessage("Request Identifier, decryption of files failed "+err.Error(), "parseFuzzRequestIdentifierHeader", "SEVERE")
			return
		}
		logger.Debugln("Request Identifier, Decrypted Files = ", filesToCreate)
		nrRequestIdentifier.TempFiles = createFuzzFileTemp(filesToCreate)
	}

	return
}

func createFuzzFileTemp(filesToCreate string) (tmpFiles []string) {

	allFiles := strings.Split(filesToCreate, COMMA_DELIMETER)

	for i := range allFiles {
		fileName := allFiles[i]
		dsFilePath := filepath.Join(secConfig.GlobalInfo.SecurityHomePath(), "nr-security-home", "tmp")
		fileName = strings.Replace(fileName, "{{NR_CSEC_VALIDATOR_HOME_TMP}}", dsFilePath, -1)
		fileName = strings.Replace(fileName, "%7B%7BNR_CSEC_VALIDATOR_HOME_TMP%7D%7D", dsFilePath, -1)

		absfileName, _ := filepath.Abs(fileName)
		if absfileName != "" {
			fileName = absfileName
		}

		tmpFiles = append(tmpFiles, fileName)
		dir := filepath.Dir(fileName)
		if dir != "" {
			err := os.MkdirAll(dir, 0770)
			if err != nil {
				logger.Debugln("Failed to create directory : ", err.Error())
			}
		}
		emptyFile, err := os.Create(fileName)
		if err != nil {
			logger.Debugln("Failed to create file : ", err.Error(), fileName)
		}
		emptyFile.Close()
	}
	return tmpFiles
}

func ToOneValueMap(header map[string][]string) (filterHeader map[string]string) {
	if header == nil {
		return
	}
	filterHeader = map[string]string{}
	for k, v := range header {
		filterHeader[k] = strings.Join(v, ",")
	}
	return
}

func isSkipIastScanApi(url, route string) (bool, string) {
	regexp := secConfig.GlobalInfo.SkipIastScanApi()
	for i := range regexp {
		re := regexp2.MustCompile(regexp[i], 0)
		if isMatch, _ := re.MatchString(url); isMatch {
			return true, regexp[i]
		}
		if isMatch, _ := re.MatchString(route); isMatch {
			return true, regexp[i]
		}
	}
	return false, ""
}

func InitLowSeverityEventScheduler() {
	t := time.NewTicker(30 * time.Minute)
	for {
		select {
		case <-t.C:
			secConfig.Secure.CleanLowSeverityEvent()
		}
	}
}
