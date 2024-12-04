// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package security_implementation

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	logging "github.com/newrelic/csec-go-agent/internal/security_logs"
	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
	eventGeneration "github.com/newrelic/csec-go-agent/security_event_generation"
)

var prepareQuery = sync.Map{}
var logger = logging.GetLogger("impl")
var grpcMap = sync.Map{}
var fastHttpMap = sync.Map{}
var requestMap = sync.Map{}
var lowSeverityEventMap = sync.Map{}

const (
	identity        = "github.com/newrelic/csec-go-agent"
	SKIP_RXSS_EVENT = "Skipping RXSS event transmission: Content type not supported for RXSS event validation"
)

type grpcConn struct {
	ClientIp   string
	ClientPort string
}

type Secureimpl struct {
}

/**
 * Implementation for SQL query
 */

func (k Secureimpl) SecurePrepareStatement(q, p string) {
	prepareQuery.Store(p, q)
}

func (k Secureimpl) SecureExecPrepareStatement(qAddress string, qargs interface{}) *secUtils.EventTracker {
	qurey, _ := prepareQuery.Load(qAddress)
	prepareQuery.Delete(qAddress)
	var arg11 []interface{}

	tmpMap := map[string]interface{}{
		"query":      qurey,
		"parameters": qargs,
	}
	arg11 = append(arg11, tmpMap)
	return k.SendEvent("SQL_DB_COMMAND", "SQLITE", arg11)
}

/**
 * Implementation for HTTPS request
 */

func (k Secureimpl) AssociateInboundRequest(r *secUtils.Info_req) {
	if !isAgentReady() {
		return
	}
	goroutineID := getID()
	if r.Request.IsGRPC {
		data, err := grpcMap.Load(goroutineID)
		if err {
			reqData := data.(grpcConn)
			r.Request.ClientIP = reqData.ClientIp
			r.Request.ClientPort = reqData.ClientPort
		}

	}
	//UpdateHttpConnsIn(r)
	associate(goroutineID, r.TraceId, r)
}

func (k Secureimpl) AssociateResponseBody(traceID, body string) {
	r := getRequestDoubleCheck(traceID)
	if r != nil {
		r.ResponseBody = r.ResponseBody + body

		// Calculate API ID and vulnerability details for RXSS event at the time of the last response.
		if r.VulnerabilityDetails.APIID == "" {
			r.VulnerabilityDetails = presentStack(r.Request.Method, "REFLECTED_XSS")
		}
	}
}

func (k Secureimpl) AssociateResponseHeader(traceID string, header http.Header) {
	r := getRequestDoubleCheck(traceID)
	if r != nil && len(header) > 0 {
		r.ResponseHeader = header
		r.ResponseContentType = header.Get("content-type")
	}
}

// func (k Secureimpl) DissociateInboundRequest() {
// 	if !isAgentReady() {
// 		return
// 	}
// 	disassociate(getID())
// }

func (k Secureimpl) AssociateOutboundRequest(dest, dport, urlx string) {
	//UpdateHttpConnsOut(dest, dport, urlx)
}

func (k Secureimpl) calculateOutboundApiId() {
	request := getRequest(getID())
	if request.VulnerabilityDetails.APIID == "" {
		vulnerabilityDetails := presentStack(request.Request.Method, "REFLECTED_XSS")
		request.VulnerabilityDetails = vulnerabilityDetails
	}
}

// func (k Secureimpl) GetRequest() *secUtils.Info_req {
// 	req, ok := requestMap.Load(getID())
// 	if ok && req != nil {
// 		return req.(*secUtils.Info_req)
// 	}
// 	return nil
// }

/**
 * Implementation for gRPC frameworks
 */

func (k Secureimpl) AssociateGrpcQueryParam(body interface{}, messageType, version string) {

	request := getRequest(getID())
	if request == nil {
		logger.Debugln("(AssociateGrpcQueryParam) GRPC Request Not Found")
		return
	}
	request.Request.IsGRPC = true
	request.ReflectedMetaData.GrcpMessageType = messageType
	request.ReflectedMetaData.GrcpMessageVersion = version
	request.GrpcBody = append(request.GrpcBody, body)

}

func (k Secureimpl) AssociateGrpcInfo(isClientStream, isServerStream bool) {
	request := getRequest(getID())
	if request == nil {
		logger.Debugln("(AssociateGrpcInfo) GRPC Request Not Found")
		return
	}
	request.ReflectedMetaData.IsGrpcClientStream = isClientStream
	request.ReflectedMetaData.IsServerStream = isServerStream

}

func (k Secureimpl) AssociateGrpcDataBytes(data []byte) bool {
	request := getRequest(getID())
	if request == nil {
		logger.Errorln("(AssociateGrpcDataBytes) GRPC Request Not Found creating new request without headers")
		return false
	}
	// request.GrpcByte = append(request.GrpcByte, data) // deprecated
	return true
}

func (k Secureimpl) AssociateGrpcData(clientIp, clientPort string) {

	data := grpcConn{clientIp, clientPort}
	cr := getID()
	grpcMap.Store(cr, data)
}
func (k Secureimpl) DisassociateGrpcData() {
	cr := getID()
	grpcMap.Delete(cr)
}

/**
 * Implementation for FastHttp frameworks
 */

func (k Secureimpl) AssociateFastHttpData(data net.Conn) {
	if data != nil {
		fastHttpMap.Store(getID(), data)
	}
}
func (k Secureimpl) GetFastHttpData() (data net.Conn) {
	data1, err := fastHttpMap.Load(getID())
	if !err {
		return nil
	}
	return data1.(net.Conn)
}
func (k Secureimpl) DisassociateFastHttpData() {
	fastHttpMap.Delete(getID())
}

func (k Secureimpl) GetFuzzHeader() string {
	request := getRequest(getID())
	if request == nil {
		return ""
	} else {
		return request.RequestIdentifier.Raw
	}
}

// func (k Secureimpl) GetTmpFiles() []string {
// 	request := getRequest(getID())
// 	if request == nil {
// 		return make([]string, 0)
// 	} else {
// 		disassociate(getID())
// 		return request.RequestIdentifier.TempFiles
// 	}
// }

/**
 * Implementation for goroutines (created and deleted)
 */

// deprecated
func (k Secureimpl) AssociateGoRoutine(caller, callee int64) {
	//Note: cannot place any Logging in this method - called from newproc
	cr := strconv.FormatInt(caller, 10)
	ce := strconv.FormatInt(callee, 10)
	associateGoroutine(cr, ce)
}

func (k Secureimpl) NewGoroutine() interface{} {
	//Note: cannot place any Logging in this method - called from newproc
	req, ok := requestMap.Load(getID())
	if ok && req != nil {
		return req
	}
	return nil
}

func (k Secureimpl) NewGoroutineLinker(req interface{}) {
	if req != nil {
		associateGoroutine(getID(), req)
	}
}

/**
 * Implementation for goroutines (created and deleted)
 */

func (k Secureimpl) SendPanicEvent(message string) {
	id := getID()
	req := getRequest(id)
	if !isAgentReady() || (req == nil) {
		logger.Debugln("panic report", "no incoming skipping Event")
		return
	}

	stack := getStackTrace()
	panic := eventGeneration.Panic{
		Message:    message,
		Type:       "Panic",
		Stacktrace: stack,
	}
	key := message + stack[0]

	eventGeneration.StoreApplicationRuntimeError(req, panic, key)
}

func (k Secureimpl) Send5xxEvent(code int) {
	id := getID()
	req := getRequest(id)
	if !isAgentReady() || (req == nil) {
		logger.Debugln("5xx report", "no incoming skipping Event")
		return
	}
	r := req.Request.Route
	if r == "" {
		r = req.Request.URL
	}
	key := r + strconv.Itoa(code)
	eventGeneration.Store5xxError(req, key, code)
}

func (k Secureimpl) SendEvent(caseType, eventCategory string, args interface{}) *secUtils.EventTracker {
	secConfig.AddEventDataToListener(secConfig.TestArgs{Parameters: fmt.Sprintf("%v", args), CaseType: caseType})
	if !isAgentReady() {
		return nil
	}
	eventId := increaseCount()
	return sendEvent(eventId, caseType, eventCategory, args, false)
}

func (k Secureimpl) SendLowSeverityEvent(caseType, eventCategory string, args interface{}) *secUtils.EventTracker {
	secConfig.AddEventDataToListener(secConfig.TestArgs{Parameters: fmt.Sprintf("%v", args), CaseType: caseType})
	if !isAgentReady() {
		return nil
	}
	eventId := increaseCount()
	return sendEvent(eventId, caseType, eventCategory, args, true)
}

func (k Secureimpl) SendExitEvent(event *secUtils.EventTracker) {
	if event == nil {
		return
	}
	if !secConfig.GlobalInfo.IsIASTEnable() {
		return
	}
	requestIdentifier := event.RequestIdentifier

	if !(requestIdentifier != "" && secUtils.CaseInsensitiveContains(requestIdentifier, event.APIID) && secUtils.CaseInsensitiveContains(requestIdentifier, ":IAST:VULNERABLE:IAST:")) {
		return
	}

	eventGeneration.SendExitEvent(event, requestIdentifier)
}

func (k Secureimpl) CleanLowSeverityEvent() {
	lowSeverityEventMap = sync.Map{}
}

func sendEvent(eventId, caseType, eventCategory string, args interface{}, isLowSeverityEvent bool) *secUtils.EventTracker {
	id := getID()
	req := getRequest(id)
	if !isAgentReady() || (req == nil) {
		logger.Debugln(caseType, "no incoming skipping Event")
		return nil
	}
	var vulnerabilityDetails secUtils.VulnerabilityDetails
	if caseType == "REFLECTED_XSS" && (*req).VulnerabilityDetails.APIID != "" {
		vulnerabilityDetails = (*req).VulnerabilityDetails
	} else {
		vulnerabilityDetails = presentStack((*req).Request.Method+"||"+(*req).Request.Route, caseType)
	}
	if isLowSeverityEvent {
		if _, ok := lowSeverityEventMap.Load(vulnerabilityDetails.APIID); ok {
			return nil
		} else {
			lowSeverityEventMap.Store(vulnerabilityDetails.APIID, 1)
		}
	}

	return eventGeneration.SendVulnerableEvent(req, caseType, eventCategory, args, vulnerabilityDetails, getEventID(eventId, id))

}

/**
 * Sync Map operations
 */

// associate request with goroutines ID
func associate(id, id1 string, a *secUtils.Info_req) {
	requestMap.Store(id, a)
	requestMap.Store(id1, a)
}

// disassociate request with goroutines ID
func disassociate(id, id1 string) {
	requestMap.Delete(id)
	if id1 != "" {
		requestMap.Delete(id1)
	}
}

// get Http request with goroutines ID
func getRequest(id string) *secUtils.Info_req {
	req, ok := requestMap.Load(id)
	if ok && req != nil {
		return req.(*secUtils.Info_req)
	}
	return nil
}

func getRequestDoubleCheck(traceId string) *secUtils.Info_req {

	if traceId == "" {
		return getRequest(getID())
	}
	req, ok := requestMap.Load(traceId)
	if ok && req != nil {
		return req.(*secUtils.Info_req)
	}
	return nil
}

// Sync Map associate operations for go routines
func associateGoroutine(caller string, req interface{}) {
	if req != nil {
		requestMap.Store(caller, req)
	}
}

// func isUser(aMethod, aFile, prevMethod, prevFile string) bool {

// 	// either reach main package OR different prefix.
// 	i := strings.LastIndex(aMethod, "/")
// 	aprefix := aMethod
// 	if i >= 0 {
// 		aprefix = aMethod[:i]
// 	}
// 	j := strings.LastIndex(prevMethod, "/")
// 	pprefix := prevMethod
// 	if j >= 0 {
// 		pprefix = prevMethod[:j]
// 	}
// 	if aprefix != pprefix {
// 		return true
// 	}
// 	if strings.HasPrefix(aMethod, "main.") {
// 		return true
// 	}
// 	return false
// }

func getID() string {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	id := string(b)
	return id
}

func getEventID(id, gid string) string {
	id = gid + ":" + id
	return id
}

func init() {
	linkMap = make(map[uintptr]hookedMethodTuple, 0)
	buildInfo, _ = debug.ReadBuildInfo()

}

func isAgentReady() bool {
	return secConfig.SecureWS != nil
}

func presentStack(method, caseType string) (vulnerabilityDetails secUtils.VulnerabilityDetails) {
	pc := make([]uintptr, 20)
	n := runtime.Callers(4, pc)
	frames := runtime.CallersFrames(pc[:n])
	id := identity
	var stackTrace []string

	generateStackTrace := func(funcName, fName, line string) {
		if !strings.HasPrefix(funcName, id) {
			tmp := funcName + "(" + fName + ":" + line + ")"
			stackTrace = append(stackTrace, tmp)
		}
	}

	isuserSet := false
	isSourceSet := false
	for {
		frame, more := frames.Next()
		functionName := frame.Function
		fileName := frame.File
		lineNumber := strconv.Itoa(frame.Line)

		if !isuserSet && isusercode(functionName, fileName) {
			vulnerabilityDetails.UserFileName = fileName
			vulnerabilityDetails.UserMethodName = functionName
			vulnerabilityDetails.LineNumber = lineNumber
			isuserSet = true
		}
		isSecureAgentCode := isSecureAgentCode(functionName)
		if !isSourceSet && !isSecureAgentCode {
			vulnerabilityDetails.SourceMethod = functionName
			isSourceSet = true
		} else if !isSourceSet {
			u := frame.Entry
			check, k := linkMapLookup(u)
			if check {
				vulnerabilityDetails.SourceMethod = k.functionName
				isSourceSet = true
				functionName = k.functionName
				fileName = k.fileName
				lineNumber = k.lineNumber
			}
		}
		if !isSecureAgentCode && !isStartProcessHook(functionName) {
			generateStackTrace(fileName, functionName, lineNumber)
		}
		if !more {
			if !isuserSet {
				vulnerabilityDetails.UserFileName = fileName
				vulnerabilityDetails.UserMethodName = functionName
				vulnerabilityDetails.LineNumber = lineNumber
			}
			break
		}
	}

	apiString := strings.Join(stackTrace, "||")
	apiId := secUtils.StringSHA256(apiString + "||" + method)

	if len(stackTrace) > 120 {
		stackTrace = stackTrace[:120]
	}

	vulnerabilityDetails.APIID = caseType + "-" + apiId
	vulnerabilityDetails.Stacktrace = stackTrace

	return vulnerabilityDetails
}

var buildInfo *debug.BuildInfo

func isusercode(name, path string) bool {
	for _, dependencie := range buildInfo.Deps {
		// element third part packages
		if strings.Contains(name, dependencie.Path) && !strings.Contains(dependencie.Version, "devel") {
			return false
		}
	}

	// handle standard packages
	return !secUtils.CaseInsensitiveContains(path, "go/src")

}

func isSecureAgentCode(name string) bool {

	if strings.Contains(name, "github.com/newrelic/go-agent") || strings.Contains(name, "github.com/newrelic/csec-go-agent") {
		return true
	}

	return false
}

func isStartProcessHook(functionName string) bool {
	return functionName == "os/exec.(*Cmd).Start"
}

func increaseCount() string {
	eventCount := atomic.LoadUint64(&secConfig.GlobalInfo.InstrumentationData.HookCalledCount)
	atomic.AddUint64(&secConfig.GlobalInfo.InstrumentationData.HookCalledCount, 1)
	return strconv.FormatUint(eventCount, 10)
}

func getStackTrace() []string {
	pc := make([]uintptr, secConfig.MaxStackTraceFrames)
	n := runtime.Callers(7, pc)
	frames := runtime.CallersFrames(pc[:n])
	id := identity
	var stackTrace []string

	generateStackTrace := func(funcName, fName, line string) {
		if !strings.HasPrefix(funcName, id) {
			tmp := funcName + "(" + fName + ":" + line + ")"
			stackTrace = append(stackTrace, tmp)
		}
	}
	for {
		frame, more := frames.Next()
		functionName := frame.Function
		fileName := frame.File
		lineNumber := strconv.Itoa(frame.Line)
		generateStackTrace(fileName, functionName, lineNumber)
		if !more {
			break
		}
	}
	return stackTrace
}
