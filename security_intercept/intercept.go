// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package security_intercept

/**
 * Function alone with this package is used for Preprocess incoming data from hooked functions..
 * Collect function arguments and generate an event with specific case-type
 */

import (
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
	NR_CSEC_FUZZ_REQUEST_ID = "nr-csec-fuzz-request-id"
	NR_CSEC_PARENT_ID       = "NR-CSEC-PARENT-ID"
	COMMA_DELIMETER         = ","
	AttributeCsecRoute      = "ROUTE"
	SKIP_RXSS_EVENT         = "Skipping RXSS event transmission: Content type not supported for RXSS event validation"
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
	if secConfig.GlobalInfo.IsInvalidFileAccessEnabled() {
		return nil
	}
	securityHomePath := secConfig.GlobalInfo.SecurityHomePath()
	if securityHomePath != "" && secUtils.CaseInsensitiveContains(fname, filepath.Join(securityHomePath, "nr-security-home", "logs")) {
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

	absolutePath, err := fileAbs(fname)
	if err != nil {
		args = append(args, fname)
	} else {
		args = append(args, absolutePath)
	}
	if isFileOpen && isFileModified(flag) && fileInApplicationPath(fname) && fileExecByExtension(fname) {
		return secConfig.Secure.SendEvent("FILE_INTEGRITY", "FILE_INTEGRITY", args)
	} else {
		return secConfig.Secure.SendEvent("FILE_OPERATION", "FILE_INTEGRITY", args)
	}
}

/**
 * Handling for System command hooks
 */

func TraceSystemCommand(command string) *secUtils.EventTracker {
	if !isAgentInitialized() || command == "" || secConfig.GlobalInfo.IsCommandInjectionEnabled() {
		return nil
	}
	var arg []string
	arg = append(arg, command)
	return secConfig.Secure.SendEvent("SYSTEM_COMMAND", "SYSTEM_COMMAND", arg)

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
	if !isAgentInitialized() || secConfig.GlobalInfo.IsNosqlInjectionEnabled() {
		return nil
	}
	if len(arguments) == 0 {
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
	return secConfig.Secure.SendEvent("NOSQL_DB_COMMAND", "MONGO", arg12)

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
	if !isAgentInitialized() || secConfig.GlobalInfo.IsSQLInjectionEnabled() {
		return nil
	}
	if query == "" {
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

	return secConfig.Secure.SendEvent("SQL_DB_COMMAND", "SQLITE", arg11)
}

func TracePrepareStatement(q, p string) {
	if !isAgentInitialized() || secConfig.GlobalInfo.IsSQLInjectionEnabled() {
		return
	}
	if q == "" {
		return
	}
	secConfig.Secure.SecurePrepareStatement(q, p)
}

func TraceExecPrepareStatement(q_address string, args ...interface{}) *secUtils.EventTracker {
	if !isAgentInitialized() || secConfig.GlobalInfo.IsSQLInjectionEnabled() {
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
	if !isAgentInitialized() || a == "" || secConfig.GlobalInfo.IsXpathInjectionEnabled() {
		return nil
	}
	var arg []string
	arg = append(arg, a)
	return secConfig.Secure.SendEvent("XPATH", "XPATH", arg)
}

/**
 * Handling for Ldap operations
 */

func TraceLdapOperation(a map[string]string) *secUtils.EventTracker {
	if !isAgentInitialized() || secConfig.GlobalInfo.IsLdapInjectionEnabled() {
		return nil
	}
	var arg []interface{}
	arg = append(arg, a)
	return secConfig.Secure.SendEvent("LDAP", "LDAP", arg)
}

/**
 * Handling for JS operations
 */

func TraceJsOperation(a string) *secUtils.EventTracker {
	if !isAgentInitialized() || a == "" || secConfig.GlobalInfo.IsJavascriptInjectionEnabled() {
		return nil
	}
	var arg []string
	arg = append(arg, a)

	return secConfig.Secure.SendEvent("JAVASCRIPT_INJECTION", "JAVASCRIPT_INJECTION", arg)
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

	secConfig.GlobalInfo.ApplicationInfo.SetServerIp(ip)

	if port == "" {
		return
	}

	a, _ := strconv.Atoi(port)

	if !secUtils.Contains(secConfig.GlobalInfo.ApplicationInfo.GetPorts(), a) {
		secConfig.GlobalInfo.ApplicationInfo.SetPorts(a)
	}
}

/**
 * Handling inbound request
 */

// TraceIncommingRequest - interception of incoming request

func TraceIncommingRequest(url, host string, hdrMap map[string][]string, method string, body string, queryparam map[string][]string, protocol, serverName, reqtype string, bodyReader secUtils.SecWriter, csecAttributes map[string]any) {
	if !isAgentInitialized() {
		return
	}
	route := ""
	for k, v := range csecAttributes {
		if secUtils.CaseInsensitiveEquals(k, AttributeCsecRoute) {
			route, _ = v.(string)
		}
	}

	if ok, _ := isSkipIastScanApi(url, route); ok {
		return
	}

	infoReq := new(secUtils.Info_req)
	infoReq.Request.URL = url
	infoReq.Request.Route = route
	infoReq.Request.ParameterMap = queryparam
	infoReq.Request.ClientIP, infoReq.Request.ClientPort = getIpAndPort(host)
	infoReq.Request.ServerPort = getServerPort()
	infoReq.Request.Headers = ToOneValueMap(hdrMap)
	infoReq.Request.Method = method
	infoReq.Request.Body = body
	infoReq.Request.BodyReader = bodyReader
	infoReq.Request.Protocol = protocol
	infoReq.Request.ContentType = getContentType(hdrMap)
	infoReq.ReqTraceData = getHeaderValue(hdrMap, NR_CSEC_TRACING_DATA)
	infoReq.RequestIdentifier = parseFuzzRequestIdentifierHeader(getHeaderValue(hdrMap, NR_CSEC_FUZZ_REQUEST_ID))
	infoReq.Request.ServerName = serverName
	infoReq.BodyLimit = secConfig.GlobalInfo.BodyLimit()
	infoReq.ParentID = getHeaderValue(hdrMap, NR_CSEC_PARENT_ID)

	if reqtype == "gRPC" {
		infoReq.Request.IsGRPC = true
	}

	secConfig.Secure.AssociateInboundRequest(infoReq)
}

func associateResponseBody(body string) {
	r := secConfig.Secure.GetRequest()
	if r != nil {
		r.ResponseBody = r.ResponseBody + body
		secConfig.Secure.CalculateOutboundApiId()
	}
}

func associateResponseHeader(header http.Header) {
	r := secConfig.Secure.GetRequest()
	if r != nil {
		r.ResponseHeader = header
		r.ResponseContentType = header.Get("content-type")
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
	// deprecated
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
	tmpFiles := secConfig.Secure.GetTmpFiles()
	secConfig.Secure.DissociateInboundRequest()
	removeFuzzFile(tmpFiles)
}

func traceResponseOperations() {
	if !isAgentInitialized() {
		return
	}

	r := secConfig.Secure.GetRequest()
	if r != nil {
		checkSecureCookies(r.ResponseHeader)
		xssCheck(r)
	}
}

func checkSecureCookies(responseHeader http.Header) {
	if responseHeader != nil {
		logger.Debugln("Verifying SecureCookies, response header", responseHeader)
		tmpRes := http.Response{Header: responseHeader}
		cookies := tmpRes.Cookies()
		var arg []map[string]interface{}
		check := false
		for _, cookie := range cookies {
			check = true
			arg = append(arg, map[string]interface{}{
				"name":       cookie.Name,
				"isHttpOnly": cookie.HttpOnly,
				"isSecure":   cookie.Secure,
				"value":      cookie.Value,
			})
		}
		if check {
			secConfig.Secure.SendEvent("SECURE_COOKIE", "SECURE_COOKIE", arg)
		}
	}
}

func xssCheck(r *secUtils.Info_req) {
	if IsRxssEnabled() && r.ResponseBody != "" {

		contentType := r.ResponseContentType
		if !secUtils.IsContentTypeSupported(contentType) {
			SendLogMessage(SKIP_RXSS_EVENT+contentType, "XssCheck", "SEVERE")
			logger.Debugln(SKIP_RXSS_EVENT, contentType)
			return
		}

		// Double check befor rxss event validation becouse in some case we don't have contentType in response header.
		cType := http.DetectContentType([]byte(r.ResponseBody))
		if !secUtils.IsContentTypeSupported(cType) {
			SendLogMessage(SKIP_RXSS_EVENT+cType, "XssCheck", "SEVERE")
			logger.Debugln(SKIP_RXSS_EVENT, cType)
			return
		}
		if r.ResponseContentType == "" {
			r.ResponseContentType = cType
		}

		out := secUtils.CheckForReflectedXSS(r)
		logger.Debugln("RXSS check result: Out value set to ", out)

		if len(out) == 0 && !secConfig.GlobalInfo.IsIASTEnable() {
			logger.Debugln("No need to send xss event as not attack and dynamic scanning is false")
		} else {
			var arg []string
			arg = append(arg, out)
			arg = append(arg, r.ResponseBody)
			secConfig.Secure.SendEvent("REFLECTED_XSS", "REFLECTED_XSS", arg)
		}
	}

}

/**
 * Handling for IAST mode
 */

func removeFuzzFile(tmpFiles []string) {
	for _, path := range tmpFiles {
		err := os.Remove(path)
		if err != nil {
			logger.Debugln("Error while removing created file : ", err.Error(), path)
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
	value += " " + secConfig.GlobalInfo.ApplicationInfo.GetAppUUID() + "/" + event.APIID + "/" + event.ID + ";"
	return NR_CSEC_TRACING_DATA, strings.TrimSpace(value)

}

func GetDummyEventTracker() *secUtils.EventTracker {
	return &secUtils.EventTracker{}
}

// GetApiCaller - Populate the ApiCallerId for microservice validation
func GetApiCaller(url string) string {
	port := ""
	applicationPort := secConfig.GlobalInfo.ApplicationInfo.GetPorts()
	if applicationPort != nil && len(applicationPort) > 0 {
		port = secUtils.IntToString(applicationPort[0])
	}
	url = secUtils.CanonicalURL(url)
	durl := base64.StdEncoding.EncodeToString([]byte(url))
	id := fmt.Sprintf("%s||%s||%s||%s", secConfig.GlobalInfo.ApplicationInfo.GetAppUUID(), secConfig.GlobalInfo.ApplicationInfo.GetContextPath(), port, durl)
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
	secConfig.GlobalInfo.ApplicationInfo.SetServerName(server_name)

	if secConfig.GlobalInfo.MetaData.GetAccountID() != "" {
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
	if secConfig.GlobalInfo.MetaData.GetAgentRunId() == "" {
		secConfig.GlobalInfo.MetaData.SetLinkingMetadata(linkingMetadata)
		accountId, ok := linkingMetadata["accountId"]
		if ok {
			secConfig.GlobalInfo.MetaData.SetAccountID(accountId)
		}
		agentRunId, ok := linkingMetadata["agentRunId"]
		if ok {
			secConfig.GlobalInfo.MetaData.SetAgentRunId(agentRunId)
		}
		entityGuid, ok := linkingMetadata["entity.guid"]
		if ok {
			secConfig.GlobalInfo.MetaData.SetEntityGuid(entityGuid)
		}
		entityname, ok := linkingMetadata["entity.name"]
		if ok {
			secConfig.GlobalInfo.MetaData.SetEntityName(entityname)
		}
		if !IsDisable() && !IsForceDisable() {
			go secWs.InitializeWsConnecton()
		}
	} else {
		secConfig.GlobalInfo.MetaData.SetLinkingMetadata(linkingMetadata)
		agentRunId, ok := linkingMetadata["agentRunId"]
		if ok {
			secConfig.GlobalInfo.MetaData.SetAgentRunId(agentRunId)
		}
		if secConfig.SecureWS != nil {
			SendLogMessage("Reconnect security agent at refresh call", "UpdateLinkData", "INFO")
			secConfig.SecureWS.ReconnectAtAgentRefresh()
		}
	}

}

func SendLogMessage(message, caller, logLevel string) {
	eventGeneration.SendLogMessage(message, caller, logLevel)
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
	defer recoverFromPanic("SendEventApi")

	switch caseType {
	case "INBOUND":
		inboundcallHandler(data...)
	case "INBOUND_END":
		traceResponseOperations()
		DissociateInboundRequest()
	case "INBOUND_WRITE":
		httpresponseHandler(data...)
	case "INBOUND_RESPONSE_CODE":
		httpresponseCodeHandler(data...)
	case "RESPONSE_HEADER":
		httpresponseHeader(data...)
	case "OUTBOUND":
		return outboundcallHandler(data[0])
	case "RECORD_PANICS":
		panicHandler(data)
	case "API_END_POINTS":
		apiEndPointsHandler(data...)
	case "GRPC":
		grpcRequestHandler(data...)
	case "GRPC_INFO":
		grpcInfoHandler(data...)
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
	case "DYNAMO_DB":
		dynamodbHandler(data...)
	case "REDIS":
		redisHandler(data...)

	}
	return nil
}

func inboundcallHandler(data ...interface{}) {

	csecAttributes := map[string]any{}
	if len(data) >= 2 {
		csecAttributes, _ = data[1].(map[string]any)
	}
	if len(data) < 1 {
		return
	}
	request := data[0]

	r, ok := request.(webRequestv2)
	if !ok || r == nil {
		inboundcallHandlerv1(request, csecAttributes)
		return
	}
	queryparam := map[string][]string{}
	for key, value := range r.GetURL().Query() {
		queryparam[key] = value
	}
	clientHost := r.GetRemoteAddress()
	if clientHost == "" {
		clientHost = r.GetHost()
	}

	reqBodyWriter := secUtils.SecWriter{GetBody: r.GetBody, IsDataTruncated: r.IsDataTruncated}
	TraceIncommingRequest(r.GetURL().String(), clientHost, r.GetHeader(), r.GetMethod(), "", queryparam, r.GetTransport(), r.GetServerName(), r.Type1(), reqBodyWriter, csecAttributes)
}

// merge inboundcallHandler and inboundcallHandlerv1 in the next major release(v1.0.0)
func inboundcallHandlerv1(request interface{}, csecAttributes map[string]any) {
	r, ok := request.(webRequest)
	if !ok || r == nil {
		SendLogMessage("ERROR: Request is not a type of webRequest and webRequestv2 ", "security_intercept", "SEVERE")
		logger.Errorln("request is not a type of webRequest and webRequestv2 ")
		return
	}
	queryparam := map[string][]string{}
	for key, value := range r.GetURL().Query() {
		queryparam[key] = value
	}
	clientHost := r.GetRemoteAddress()
	if clientHost == "" {
		clientHost = r.GetHost()
	}

	reqBodyWriter := secUtils.SecWriter{GetBody: r.GetBody, IsDataTruncated: IsDataTruncated}
	TraceIncommingRequest(r.GetURL().String(), clientHost, r.GetHeader(), r.GetMethod(), "", queryparam, r.GetTransport(), r.GetServerName(), r.Type1(), reqBodyWriter, csecAttributes)
}

func outboundcallHandler(req interface{}) *secUtils.EventTracker {
	if req == nil || !isAgentInitialized() {
		return nil
	}
	r, ok := req.(*http.Request)
	if !ok || r == nil || r.URL == nil || r.URL.String() == "" {
		return nil
	}
	var args []interface{}
	args = append(args, r.URL.String())
	event := secConfig.Secure.SendEvent("HTTP_REQUEST", "HTTP_REQUEST", args)
	return event
}

func httpresponseCodeHandler(data ...interface{}) {
	if len(data) < 1 {
		return
	}
	rescode, _ := data[0].(int)
	if rescode >= 500 {
		secConfig.Secure.Send5xxEvent(rescode)
	}
}

func httpresponseHandler(data ...interface{}) {
	if len(data) < 2 {
		return
	}

	contentType := ""
	if hdr, ok := data[1].(http.Header); ok && hdr != nil {
		contentType = hdr.Get("content-type")
		associateResponseHeader(hdr)
	}

	if contentType != "" && !secUtils.IsContentTypeSupported(contentType) {
		logger.Debugln("Skipping RXSS event transmission: Content type not supported for RXSS event validation", contentType)
		return
	}

	if responseBody, ok := data[0].(string); ok {
		// Double check befor rxss event validation becouse in some case we don't have contentType in response header.
		contentType = http.DetectContentType([]byte(responseBody))
		if !secUtils.IsContentTypeSupported(contentType) {
			logger.Debugln("Skipping RXSS event transmission: Content type not supported for RXSS event validation", contentType)
			return
		}
		associateResponseBody(responseBody)
	}
}

func httpresponseHeader(data ...interface{}) {
	if len(data) < 1 {
		return
	}
	if hdr, ok := data[0].(http.Header); ok && hdr != nil {
		associateResponseHeader(hdr)
	}
}

func grpcRequestHandler(data ...interface{}) {
	if data == nil || !isAgentInitialized() {
		return
	}
	if len(data) >= 3 {
		messageType, _ := data[1].(string)
		version, _ := data[2].(string)
		secConfig.Secure.AssociateGrpcQueryParam(data[0], messageType, version)
	} else {
		secConfig.Secure.AssociateGrpcQueryParam(data[0], "", "v2")
	}
}

func apiEndPointsHandler(data ...interface{}) {
	if data == nil || !isAgentInitialized() {
		return
	}
	if len(data) >= 3 {
		path, _ := data[0].(string)
		method, _ := data[1].(string)
		handler, _ := data[2].(string)
		secConfig.GlobalInfo.SetApiData(secConfig.Urlmappings{
			Path:    path,
			Method:  method,
			Handler: handler,
		})
	}
}

func grpcInfoHandler(data ...interface{}) {
	if data == nil || !isAgentInitialized() {
		return
	}
	if len(data) < 2 {
		return
	}

	isClientStream, ok := data[0].(bool)
	isServerStream, ok1 := data[1].(bool)
	if ok && ok1 {
		secConfig.Secure.AssociateGrpcInfo(isClientStream, isServerStream)
	}
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
		ProcessInit("http")
	}
}

func mongoHandler(data ...interface{}) *secUtils.EventTracker {
	if !isAgentInitialized() {
		return nil
	}
	if len(data) < 2 {
		return nil
	}
	queryType, ok := data[1].(string)
	if (ok && queryType == "delete") || !secConfig.GlobalInfo.InstrumentationData.TraceHooksApplied.Mongo {
		if secUtils.CaseInsensitiveEquals(queryType, "findAndModify") {
			queryType = "update"
		}
		var arg11 []interface{}
		var arg12 []interface{}

		var jsonMap map[string]interface{}
		arg, ok := data[0].([]byte)
		if !ok || arg == nil {
			return nil
		}
		err := json.Unmarshal(arg, &jsonMap)
		if err != nil {
			SendLogMessage("error in Unmarshal mongo arg"+err.Error(), "mongoHandler", "SEVERE")
			logger.Errorln("error in Unmarshal mongo arg", err)
			return nil
		}
		arg11 = append(arg11, jsonMap)
		tmp_map1 := map[string]interface{}{
			"payloadType": queryType,
			"payload":     arg11,
		}
		arg12 = append(arg12, tmp_map1)
		return secConfig.Secure.SendEvent("NOSQL_DB_COMMAND", "MONGO", arg12)
	}
	return nil
}
func DistributedTraceHeaders(hdrs *http.Request, secureAgentevent interface{}) {
	if secureAgentevent != nil && hdrs != nil {
		secEvent, ok := secureAgentevent.(*secUtils.EventTracker)
		if !ok || secEvent == nil {
			return
		}
		key, value := GetTraceHeader(secEvent)
		if key != "" {
			hdrs.Header.Add(key, value)
		}
		value = GetFuzzHeader()
		if value != "" {
			hdrs.Header.Add(NR_CSEC_FUZZ_REQUEST_ID, value)
		}
	}

}
func dynamodbHandler(data ...interface{}) {
	if data == nil || !isAgentInitialized() {
		return
	}
	secConfig.Secure.SendEvent("DYNAMO_DB_COMMAND", "DQL", data[0])
}

func redisHandler(data ...interface{}) {
	if data == nil || !isAgentInitialized() {
		return
	}

	secConfig.Secure.SendEvent("REDIS_DB_COMMAND", "REDIS", data)
}

func panicHandler(data ...interface{}) {

	if nil == data || len(data) == 0 || !isAgentInitialized() {
		return
	}
	panic := data[0]

	tmp := fmt.Sprintf("%s", panic)
	secConfig.Secure.SendPanicEvent(tmp)

}

func DeactivateSecurity() {
	SendLogMessage("deactivating security agent", "DeactivateSecurity", "INFO")
	eventGeneration.RemoveHcScheduler()
	eventGeneration.RemovePanicReportScheduler()
	secConfig.GlobalInfo.SetSecurityEnabled(false)
	secConfig.GlobalInfo.SetSecurityAgentEnabled(false)
	if secConfig.SecureWS != nil {
		go secConfig.SecureWS.CloseWSConnection()
	}
}

func InitHttpFuzzRestClient(rest secWs.SecureFuzz) {
	SendLogMessage("initialize http fuzz Client", "InitHttpFuzzRestClient", "INFO")
	secWs.FuzzHandler.InitHttpFuzzRestClient(rest)
}

func InitGrpsFuzzRestClient(rest secWs.SecureFuzz) {
	SendLogMessage("initialize gRPC fuzz Client", "InitGrpsFuzzRestClient", "INFO")
	secWs.FuzzHandler.InitGrpsFuzzRestClient(rest)

}

func init() {
	secConfig.Secure = secImpl.Secureimpl{}
}
