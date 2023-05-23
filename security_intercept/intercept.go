// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_intercept

/**
 * Function alone with this package is used for Preprocess incoming data from hooked functions..
 * Collect function arguments and generate an event with specific case-type
 */

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	logging "github.com/newrelic/csec-go-agent/internal/security_logs"
	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
	eventGeneration "github.com/newrelic/csec-go-agent/security_event_generation"
	secWs "github.com/newrelic/csec-go-agent/security_handlers"
	secImpl "github.com/newrelic/csec-go-agent/security_implementation"
)

var logger = logging.GetLogger("intercept")

const (
	IAST_SEP                = ":IAST:"
	EARLY_EXIT              = "Early Exit, csec agent is not initlized"
	NR_CSEC_TRACING_DATA    = "NR-CSEC-TRACING-DATA"
	NR_CSEC_FUZZ_REQUEST_ID = "NR-CSEC-FUZZ-REQUEST-ID"
)

/**
 * Handling all four types of hook methods.
 */

func InitSyms() {
	secConfig.Secure.InitSyms()
}

func HookWrap(from, to, toc interface{}) error {
	if secConfig.Secure != nil {
		return secConfig.Secure.HookWrap(from, to, toc)
	} else {
		return errors.New("agent-not-initialized")
	}
}

func HookWrapInterface(from, to, toc interface{}) error {
	if secConfig.Secure != nil {
		return secConfig.Secure.HookWrapInterface(from, to, toc)
	} else {
		return errors.New("agent-not-initialized")
	}
}

func HookWrapRaw(from uintptr, to, toc interface{}) error {
	if secConfig.Secure != nil {
		return secConfig.Secure.HookWrapRaw(from, to, toc)
	} else {
		return errors.New("agent-not-initialized")
	}
}

func HookWrapRawNamed(from string, to, toc interface{}) (string, error) {
	if secConfig.Secure != nil {
		return secConfig.Secure.HookWrapRawNamed(from, to, toc)
	} else {
		return "", errors.New("agent-not-initialized")
	}
}

/**
 * Handling for file operations hooks
 */

func TraceFileOperation(fname string, flag int, isFileOpen bool) *secUtils.EventTracker {
	if secConfig.GlobalInfo.Security.SecurityHomePath != "" && secUtils.CaseInsensitiveContains(fname, filepath.Join(secConfig.GlobalInfo.Security.SecurityHomePath, "nr-security-home", "logs")) {
		// here dont put logger, will cause issue with logrus and hook
		// the hook is for log file rotation, ignore
		return nil
	}
	if !isAgentInitialized() {
		return nil
	}
	if len(fname) < 1 || fname == "/dev/null" {
		return nil
	}
	var args []string

	args = append(args, fname)
	if isFileOpen && isFileModified(flag) && fileInApplicationPath(fname) && fileExecByExtension(fname) {
		return secConfig.Secure.SendEvent("FILE_INTEGRITY", args)
	} else {
		return secConfig.Secure.SendEvent("FILE_OPERATION", args)
	}
}

/**
 * Handling for System command hooks
 */

func TraceSystemCommand(command string) *secUtils.EventTracker {
	if !isAgentInitialized() {
		return nil
	}
	var arg []string
	arg = append(arg, command)
	return secConfig.Secure.SendEvent("SYSTEM_COMMAND", arg)

}

/**
 * Handling for Mongo operations
 */

func TraceMongoHooks(e error) {
	if e == nil {
		secConfig.GlobalInfo.InstrumentationData.TraceHooksApplied.Mongo = true
	}
}

func TraceMongoOperation(arguments []byte, queryType string) *secUtils.EventTracker {
	if !isAgentInitialized() {
		return nil
	}
	var arg11 []interface{}
	var arg12 []interface{}

	var jsonMap map[string]interface{}
	err := json.Unmarshal(arguments, &jsonMap)
	if err != nil {
		logger.Infoln("Detected Port : ")
	}
	arg11 = append(arg11, jsonMap)
	tmp_map1 := map[string]interface{}{
		"payloadType": queryType,
		"payload":     arg11,
	}

	arg12 = append(arg12, tmp_map1)
	return secConfig.Secure.SendEvent("NOSQL_DB_COMMAND", arg12)

}

/**
 * Handling for SQL operations
 */

func TraceSqlHooks(e error) {
	if e == nil {
		secConfig.GlobalInfo.InstrumentationData.TraceHooksApplied.Sql = true
	}
}

func TraceSqlOperation(query string, args ...interface{}) *secUtils.EventTracker {
	if !isAgentInitialized() {
		return nil
	}
	var arg11 []interface{}
	parameters := map[int]interface{}{}
	for i := range args {
		str := fmt.Sprintf("%v", args[i])
		parameters[i] = string(str)
	}
	tmp_map := map[string]interface{}{
		"query":      query,
		"parameters": parameters,
	}
	arg11 = append(arg11, tmp_map)

	return secConfig.Secure.SendEvent("SQL_DB_COMMAND", arg11)
}

func TracePrepareStatement(q, p string) {
	if !isAgentInitialized() {
		return
	}
	secConfig.Secure.SecurePrepareStatement(q, p)
}

func TraceExecPrepareStatement(q_address string, args ...interface{}) *secUtils.EventTracker {
	if !isAgentInitialized() {
		return nil
	}
	parameters := map[int]interface{}{}
	for i := range args {
		str := fmt.Sprintf("%v", args[i])
		parameters[i] = string(str)
	}

	return secConfig.Secure.SecureExecPrepareStatement(q_address, parameters)
}

/**
 * Handling for XPATH operations
 */

func TraceXpathOperation(a string) *secUtils.EventTracker {
	if !isAgentInitialized() {
		return nil
	}
	var arg []string
	arg = append(arg, a)
	return secConfig.Secure.SendEvent("XPATH", arg)
}

/**
 * Handling for Ldap operations
 */

func TraceLdapOperation(a map[string]string) *secUtils.EventTracker {
	if !isAgentInitialized() {
		return nil
	}
	var arg []interface{}
	arg = append(arg, a)
	return secConfig.Secure.SendEvent("LDAP", arg)
}

/**
 * Handling for JS operations
 */

func TraceJsOperation(a string) *secUtils.EventTracker {
	if !isAgentInitialized() {
		return nil
	}
	var arg []string
	arg = append(arg, a)

	return secConfig.Secure.SendEvent("JAVASCRIPT_INJECTION", arg)
}

/**
 * Handling server start case
 */
func AssociateApplicationPort(data string) {

	ip, port := getIpAndPort(data)

	if ip == "::" || ip == "" {
		ip = "localhost"
	}
	logger.Infoln("Detected Port : ", port)
	logger.Infoln("Detected Server IP : ", ip)

	secConfig.GlobalInfo.ApplicationInfo.ServerIp = ip
	if port == "" {
		return
	}

	a, _ := strconv.Atoi(port)

	if !secUtils.Contains(secConfig.GlobalInfo.ApplicationInfo.Ports, a) {
		secConfig.GlobalInfo.ApplicationInfo.Ports = append(secConfig.GlobalInfo.ApplicationInfo.Ports, a)
	}
}

/**
 * Handling inbound request
 */

// TraceIncommingRequest - interception of incoming request

func TraceIncommingRequest(url, host string, hdrMap map[string][]string, method string, body []byte, queryparam map[string][]string, protocol, serverName string) {
	if !isAgentInitialized() {
		return
	}
	clientIp := ""
	clientPort := ""
	if host != "" {
		clientIp, clientPort = getIpAndPort(host)
	}

	// filter request headers
	filterHeader := map[string]string{}
	RequestIdentifier := ""
	traceData := ""
	for k, v := range hdrMap {
		if secUtils.CaseInsensitiveEquals(k, NR_CSEC_TRACING_DATA) {
			traceData = strings.Join(v, ",")
		} else if secUtils.CaseInsensitiveEquals(k, NR_CSEC_FUZZ_REQUEST_ID) {
			RequestIdentifier = strings.Join(v, ",")
		} else {
			filterHeader[k] = strings.Join(v, ",")
		}
	}
	if traceData != "" {
		filterHeader[NR_CSEC_TRACING_DATA] = traceData
	}
	if RequestIdentifier != "" {
		filterHeader[NR_CSEC_FUZZ_REQUEST_ID] = RequestIdentifier
	}
	kb := bytes.TrimRight(body, "\x00")
	kbb := string(kb)
	// record incoming request
	infoReq := new(secUtils.Info_req)
	(*infoReq).Request.URL = url
	(*infoReq).Request.ParameterMap = queryparam
	(*infoReq).Request.ClientIP = clientIp
	(*infoReq).Request.ClientPort = clientPort
	(*infoReq).Request.ServerPort = getServerPort()
	(*infoReq).Request.IsGRPC = false
	(*infoReq).Request.Headers = filterHeader
	(*infoReq).GrpcByte = make([][]byte, 0)
	(*infoReq).Request.Method = method
	(*infoReq).Request.Body = kbb
	(*infoReq).Request.Protocol = protocol
	(*infoReq).Request.ContentType = getContentType(filterHeader)
	(*infoReq).ReqTraceData = traceData
	(*infoReq).RequestIdentifier = RequestIdentifier
	(*infoReq).Request.ServerName = serverName
	createFuzzFile(RequestIdentifier)
	secConfig.Secure.AssociateInboundRequest(infoReq)
}

func AssociateResponseBody(body, contentType string) {
	if !isAgentInitialized() {
		return
	}
	r := secConfig.Secure.GetRequest()
	if r != nil {
		r.ResponseBody = r.ResponseBody + body
		r.ResponseContentType = contentType
		secConfig.Secure.CalculateOutboundApiId()
	}
}

/**
 * Handling for FastHttp framework
 */

func AssociateFastHttpData(c net.Conn) {
	secConfig.Secure.AssociateFastHttpData(c)
}
func DissociateFastHttpData() {
	secConfig.Secure.DisassociateFastHttpData()
}
func GetFastHttpData() net.Conn {
	return secConfig.Secure.GetFastHttpData()
}

/**
 * Handling for gRPC framework
 */

// deprecated
func AssociateGrpcHeaders(hdrMap map[string]string) {
	if !isAgentInitialized() {
		return
	}
	tracerpcRequestWithHeader(hdrMap, nil)
}

// func AssociateGrpcQueryParam(body interface{}, data []byte) {
// 	if !isAgentInitialized() {
// 		return
// 	}
// 	//secConfig.Secure.AssociateGrpcQueryParam(body, data)
// }

func AssociateGrpcDataBytes(data []byte) {
	if !isAgentInitialized() {
		return
	}
	length := len(data)
	slc2 := make([]byte, length)
	copy(slc2, data)
	if !secConfig.Secure.AssociateGrpcDataBytes(slc2) {
		tracerpcRequestWithHeader(make(map[string]string), slc2)
	}

}

func ProcessGrpcResponse(service, method, reply string) {
	if !isAgentInitialized() {
		return
	}
	logger.Infoln("intercept grpc.Response: service", service, ",method:", method, ",args:", reply)
	//Don't need to process this data for XSS
	secConfig.Secure.DissociateInboundRequest()
}

func AssociateGrpcConnectionData(remoteAddr string) {
	if !isAgentInitialized() {
		return
	}

	clientIp := ""
	clientPort := ""
	if remoteAddr != "" {
		clientIp, clientPort = getIpAndPort(remoteAddr)
	}
	secConfig.Secure.AssociateGrpcData(clientIp, clientPort)
}

func DissociateGrpcConnectionData() {
	secConfig.Secure.DisassociateGrpcData()
}

func tracerpcRequestWithHeader(header map[string]string, data []byte) {
	if !isAgentInitialized() {
		return
	}
	infoReq := &secUtils.Info_req{}

	(*infoReq).Request.Headers = make(map[string]string)
	(*infoReq).Request.ParameterMap = make(map[string][]string, 0)
	(*infoReq).Request.Method = "gRPC"
	(*infoReq).Request.ServerPort = getServerPort()
	(*infoReq).Request.IsGRPC = true

	if data != nil {
		(*infoReq).GrpcByte = append((*infoReq).GrpcByte, data)
	}

	host := ""

	for k, v := range header {

		if k == ":method" {
			(*infoReq).Request.Method = v
		} else if k == ":path" {
			(*infoReq).Request.URL = v
		} else if k == ":scheme" {
			(*infoReq).Request.Protocol = v
		} else if k == "content-type" {
			(*infoReq).Request.ContentType = v
		} else if secUtils.CaseInsensitiveEquals(k, NR_CSEC_TRACING_DATA) {
			(*infoReq).ReqTraceData = v
			delete(header, k)
		} else if secUtils.CaseInsensitiveEquals(k, NR_CSEC_FUZZ_REQUEST_ID) {
			(*infoReq).RequestIdentifier = v
			delete(header, k)
		} else if secUtils.CaseInsensitiveEquals(k, ":authority") {
			(*infoReq).Request.ServerName = k
		} else if secUtils.CaseInsensitiveEquals(k, ":host") {
			host = k
		}
	}

	// reassign all deleted header
	if (*infoReq).ReqTraceData != "" {
		header[NR_CSEC_TRACING_DATA] = (*infoReq).ReqTraceData
	}
	if (*infoReq).RequestIdentifier != "" {
		header[NR_CSEC_FUZZ_REQUEST_ID] = (*infoReq).RequestIdentifier
	}
	createFuzzFile((*infoReq).RequestIdentifier)
	if (*infoReq).Request.ServerName == "" {
		(*infoReq).Request.ServerName = host
	}
	(*infoReq).Request.Headers = header
	secConfig.Secure.AssociateInboundRequest(infoReq)
}

/**
 * Handling for goroutines (created and deleted)
 */

// AssociateGoRoutine creates a copy of incoming request data associated with caller Go Routine to the callee.
func AssociateGoRoutine(caller, callee int64) {
	if secConfig.Secure == nil {
		return
	}
	secConfig.Secure.AssociateGoRoutine(caller, callee)
}

func DissociateInboundRequest() {
	secConfig.Secure.DissociateInboundRequest()
	removeFuzzFile()
}

func XssCheck() {
	if IsRXSSDisable() {
		return
	}
	if !isAgentInitialized() {
		return
	}
	r := secConfig.Secure.GetRequest()
	if r != nil && r.ResponseBody != "" {

		if r.ResponseContentType != "" && !secUtils.IsContentTypeSupported(r.ResponseContentType) {
			logger.Debugln("No need to send RXSS event ContentType not supported for rxss event validation", r.ResponseContentType)
			return
		}

		// Double check befor rxss event validation becouse in some case we don't have contentType in response header.
		cType := http.DetectContentType([]byte(r.ResponseBody))
		if !secUtils.IsContentTypeSupported(cType) {
			logger.Debugln("No need to send RXSS event ContentType not supported for rxss event validation", cType)
			return
		}
		if r.ResponseContentType != "" {
			r.ResponseContentType = cType
		}

		out := secUtils.CheckForReflectedXSS(r)
		logger.Debugln("CheckForReflectedXSS out value is : ", out)

		if len(out) == 0 && !(secConfig.GlobalInfo.CurrentPolicy.VulnerabilityScan.Enabled && secConfig.GlobalInfo.CurrentPolicy.VulnerabilityScan.IastScan.Enabled) {
			logger.Debugln("No need to send xss event as not attack and dynamic scanning is false")
		} else {
			logger.Debugln("return value of reflected xss string : ", out)
			var arg []string
			arg = append(arg, out)
			arg = append(arg, r.ResponseBody)
			secConfig.Secure.SendEvent("REFLECTED_XSS", arg)
		}
		logger.Debugln("Called check for reflected XSS" + out)
	}
}

/**
 * Handling for IAST mode
 */

// create a remove fuzz file for verfy file acesss attack
func createFuzzFile(fuzzheaders string) {
	DSON := true
	if DSON && fuzzheaders != "" {
		additionalData := strings.Split(fuzzheaders, IAST_SEP)
		logger.Debugln("additionalData:", additionalData)
		if len(additionalData) >= 7 {
			for i := 6; i < len(additionalData); i++ {
				fileName := additionalData[i]
				fileName = strings.Replace(fileName, "{{NR_CSEC_VALIDATOR_HOME_TMP}}", secConfig.GlobalInfo.Security.SecurityHomePath, -1)
				fileName = strings.Replace(fileName, "%7B%7BNR_CSEC_VALIDATOR_HOME_TMP%7D%7D", secConfig.GlobalInfo.Security.SecurityHomePath, -1)
				dir := filepath.Dir(fileName)
				if dir != "" {
					err := os.MkdirAll(dir, os.ModePerm)
					if err != nil {
						logger.Info("Error while creating file : ", err.Error())
					}
				}
				emptyFile, err := os.Create(fileName)
				if err != nil {
					logger.Info("Error while creating file : ", err.Error(), fileName)
				}
				emptyFile.Close()
			}
		}
	}
}

func removeFuzzFile() {
	fuzzheaders := secConfig.Secure.GetFuzzHeader()
	if secConfig.GlobalInfo.CurrentPolicy.VulnerabilityScan.Enabled && secConfig.GlobalInfo.CurrentPolicy.VulnerabilityScan.IastScan.Enabled && fuzzheaders != "" {
		additionalData := strings.Split(fuzzheaders, IAST_SEP)
		logger.Debugln("additionalData:", additionalData)
		if len(additionalData) >= 7 {
			for i := 6; i < len(additionalData); i++ {
				fileName := additionalData[i]
				fileName = strings.Replace(fileName, "{{NR_CSEC_VALIDATOR_HOME_TMP}}", secConfig.GlobalInfo.Security.SecurityHomePath, -1)
				fileName = strings.Replace(fileName, "%7B%7BNR_CSEC_VALIDATOR_HOME_TMP%7D%7D", secConfig.GlobalInfo.Security.SecurityHomePath, -1)
				err := os.Remove(fileName)
				if err != nil {
					logger.Errorln("Error while removing created file : ", err.Error(), fileName)
				}
			}
		}
	}
}

func GetFuzzHeader() string {
	return secConfig.Secure.GetFuzzHeader()
}

/**
 * Utility for miroservice validation
 */

func GetTraceHeader(event *secUtils.EventTracker) (string, string) {
	if event == nil {
		return "", ""
	}
	value := event.TracingHeader
	value += " " + secConfig.GlobalInfo.ApplicationInfo.AppUUID + "/" + event.APIID + "/" + event.ID + ";"
	return NR_CSEC_TRACING_DATA, strings.TrimSpace(value)

}

func GetDummyEventTracker() *secUtils.EventTracker {
	return &secUtils.EventTracker{}
}

// GetApiCaller - Populate the ApiCallerId for microservice validation
func GetApiCaller(url string) string {
	port := ""
	if secConfig.GlobalInfo.ApplicationInfo.Ports != nil && len(secConfig.GlobalInfo.ApplicationInfo.Ports) > 0 {
		port = secUtils.IntToString(secConfig.GlobalInfo.ApplicationInfo.Ports[0])
	}
	url = secUtils.CanonicalURL(url)
	durl := base64.StdEncoding.EncodeToString([]byte(url))
	id := fmt.Sprintf("%s||%s||%s||%s", secConfig.GlobalInfo.ApplicationInfo.AppUUID, secConfig.GlobalInfo.ApplicationInfo.ContextPath, port, durl)
	return id
}

func SendExitEvent(exitEvent interface{}, err error) {
	if err == nil && exitEvent != nil {
		eventTracker, ok := exitEvent.(*secUtils.EventTracker)
		if ok {
			secConfig.Secure.SendExitEvent(eventTracker)
		}
	}
}

func ProcessInit(server_name string) {
	secConfig.GlobalInfo.ApplicationInfo.ServerName = append(secConfig.GlobalInfo.ApplicationInfo.ServerName, server_name)
	if secConfig.GlobalInfo.AccountID != "" {
		eventGeneration.SendApplicationInfo()
	}
}

func UpdateLinkData(linkingMetadata map[string]string) {
	logger.Info("UpdateLinkData", linkingMetadata)

	if value, ok := linkingMetadata["entityName"]; ok {
		linkingMetadata["entity.name"] = value
		delete(linkingMetadata, "entityName")
	}

	if value, ok := linkingMetadata["entityGUID"]; ok {
		linkingMetadata["entity.guid"] = value
		delete(linkingMetadata, "entityGUID")
	}
	if secConfig.GlobalInfo.AgentRunId == "" {
		secConfig.GlobalInfo.LinkingMetadata = linkingMetadata
		accountId, ok := linkingMetadata["accountId"]
		if ok {
			secConfig.GlobalInfo.AccountID = accountId
		}
		agentRunId, ok := linkingMetadata["agentRunId"]
		if ok {
			secConfig.GlobalInfo.AgentRunId = agentRunId
		}

		if !IsDisable() && !IsForceDisable() {
			go secWs.InitializeWsConnecton()
		}
	} else {
		secConfig.GlobalInfo.LinkingMetadata = linkingMetadata
		agentRunId, ok := linkingMetadata["agentRunId"]
		if ok {
			secConfig.GlobalInfo.AgentRunId = agentRunId
		}
		secConfig.SecureWS.ReconnectAtAgentRefresh()
	}

}

// security_api handlers

func SendEvent(caseType string, data ...interface{}) interface{} {
	if data == nil || len(data) < 1 {
		logger.Errorln("Invalid api call", caseType)
		return nil
	}
	if IsDisable() {
		return nil
	}
	logger.Debugln("Sendevent api call", caseType)

	switch caseType {
	case "INBOUND":
		inboundcallHandler(data[0])
	case "INBOUND_END":
		XssCheck()
		DissociateInboundRequest()
	case "INBOUND_WRITE":
		httpresponseHandler(data...)
	case "OUTBOUND":
		return outboundcallHandler(data[0])
	case "GRPC":
		grpcRequestHandler(data[0])
	case "MONGO":
		return mongoHandler(data...)
	case "SQL":
		return sqlHandler(data...)
	case "SQL_PREPARE":
		sqlPrepareHandler(data...)
	case "SQL_PREPARE_ARGS":
		return sqlPrepareArgsHandler(data...)
	case "NEW_GOROUTINE_LINKER":
		secConfig.Secure.NewGoroutineLinker(data[0])
	case "NEW_GOROUTINE":
		return secConfig.Secure.NewGoroutine()
	case "NEW_GOROUTINE_END":
		secConfig.Secure.DissociateInboundRequest()
	case "APP_INFO":
		associateApplicationPort(data...)
	}
	return nil
}

func inboundcallHandler(request interface{}) {
	r := request.(webRequest)
	queryparam := map[string][]string{}
	for key, value := range r.GetURL().Query() {
		queryparam[key] = value
	}
	clientHost := r.GetRemoteAddress()
	if clientHost == "" {
		clientHost = r.GetHost()
	}
	TraceIncommingRequest(r.GetURL().String(), clientHost, r.GetHeader(), r.GetMethod(), r.GetBody(), queryparam, r.GetTransport(), r.GetServerName())
}

func outboundcallHandler(req interface{}) *secUtils.EventTracker {
	if req == nil || !isAgentInitialized() {
		return nil
	}
	r, ok := req.(*http.Request)
	if !ok {
		return nil
	}
	var args []interface{}
	args = append(args, r.URL.String())
	event := secConfig.Secure.SendEvent("HTTP_REQUEST", args)
	return event
}

func httpresponseHandler(data ...interface{}) {
	if len(data) < 2 {
		return
	}
	res := data[0]
	header := data[1]

	if res == nil || !isAgentInitialized() {
		return
	}
	contentType := ""
	if hdr, ok := header.(http.Header); ok {
		for key, values := range hdr {
			if secUtils.CaseInsensitiveEquals(key, "content-type") {
				contentType = strings.Join(values, ",")
			}
		}
	}

	if contentType != "" && !secUtils.IsContentTypeSupported(contentType) {
		logger.Debugln("No need to send RXSS event ContentType not supported for rxss event validation", contentType)
		return
	}

	if responseBody, ok := res.(string); ok {
		// Double check befor rxss event validation becouse in some case we don't have contentType in response header.
		cType := http.DetectContentType([]byte(responseBody))
		if !secUtils.IsContentTypeSupported(cType) {
			logger.Debugln("No need to send RXSS event ContentType not supported for rxss event validation", cType)
			return
		}

		AssociateResponseBody(responseBody, contentType)
	}
}

func grpcRequestHandler(data interface{}) {
	if data == nil || !isAgentInitialized() {
		return
	}
	secConfig.Secure.AssociateGrpcQueryParam(data)
}

func sqlHandler(data ...interface{}) *secUtils.EventTracker {
	if data == nil || !isAgentInitialized() {
		return nil
	}
	if !secConfig.GlobalInfo.InstrumentationData.TraceHooksApplied.Sql {
		query, ok := data[0].(string)
		if ok {
			return TraceSqlOperation(query, data[1])
		}
	}
	return nil
}

func sqlPrepareHandler(data ...interface{}) {
	if data == nil || !isAgentInitialized() {
		return
	}
	if !secConfig.GlobalInfo.InstrumentationData.TraceHooksApplied.Sql {
		query, ok := data[0].(string)
		address, ok1 := data[1].(string)
		if ok && ok1 {
			TracePrepareStatement(query, address)
		}
	}
}

func sqlPrepareArgsHandler(data ...interface{}) *secUtils.EventTracker {
	if data == nil || !isAgentInitialized() {
		return nil
	}
	if !secConfig.GlobalInfo.InstrumentationData.TraceHooksApplied.Sql {
		address, ok := data[1].(string)
		if ok {
			return TraceExecPrepareStatement(address, data[0])
		}
	}
	return nil
}

func associateApplicationPort(data ...interface{}) {
	add, ok := data[0].(string)
	if ok {
		AssociateApplicationPort(add)
	}
}

func mongoHandler(data ...interface{}) *secUtils.EventTracker {
	if !isAgentInitialized() {
		return nil
	}
	queryType, ok := data[1].(string)
	if (ok && queryType == "delete") || !secConfig.GlobalInfo.InstrumentationData.TraceHooksApplied.Mongo {

		var arg11 []interface{}
		var arg12 []interface{}

		var jsonMap map[string]interface{}
		arg, ok := data[0].([]byte)
		if !ok {
			return nil
		}
		err := json.Unmarshal(arg, &jsonMap)
		if err != nil {
			logger.Errorln("error in Unmarshal mongo arg", err)
			return nil
		}
		arg11 = append(arg11, jsonMap)
		tmp_map1 := map[string]interface{}{
			"payloadType": queryType,
			"payload":     arg11,
		}
		arg12 = append(arg12, tmp_map1)
		return secConfig.Secure.SendEvent("NOSQL_DB_COMMAND", arg12)
	}
	return nil
}

func DistributedTraceHeaders(hdrs *http.Request, secureAgentevent interface{}) {
	if secureAgentevent != nil {
		secEvent := secureAgentevent.(*secUtils.EventTracker)
		key, value := GetTraceHeader(secEvent)
		if key != "" {
			hdrs.Header.Add(key, value)
		}
		value = GetFuzzHeader()
		if value != "" {
			hdrs.Header.Add("NR_CSEC_FUZZ_REQUEST_ID", value)
		}
	}

}

func DeactivateSecurity() {
	eventGeneration.RemoveHcScheduler()
	secConfig.GlobalInfo.Security.Enabled = false
	secConfig.GlobalInfo.Security.Agent.Enabled = false
	if secConfig.SecureWS != nil {
		go secConfig.SecureWS.CloseWSConnection()
	}
}

func InitHttpFuzzRestClient(rest secWs.SecureFuzz) {
	secWs.FuzzHandler.InitHttpFuzzRestClient(rest)
}

func InitGrpsFuzzRestClient(rest secWs.SecureFuzz) {
	secWs.FuzzHandler.InitGrpsFuzzRestClient(rest)

}

func init() {
	secConfig.Secure = secImpl.Secureimpl{}
}
