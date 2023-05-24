// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_implementation

import (
	"bytes"
	"fmt"
	"net"
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

const (
	identity = "github.com/newrelic/csec-go-agent"
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

func (k Secureimpl) SecureExecPrepareStatement(q_address string, qargs interface{}) *secUtils.EventTracker {
	qurey, _ := prepareQuery.Load(q_address)
	prepareQuery.Delete(q_address)
	var arg11 []interface{}

	tmp_map := map[string]interface{}{
		"query":      qurey,
		"parameters": qargs,
	}
	arg11 = append(arg11, tmp_map)
	return k.SendEvent("SQL_DB_COMMAND", arg11)
}

/**
 * Implementation for HTTPS request
 */

func (k Secureimpl) AssociateInboundRequest(r *secUtils.Info_req) {
	if !isAgentReady() {
		return
	}
	secConfig.GlobalInfo.EventData.HTTPRequestCount++
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
	associate(goroutineID, r)
}

func (k Secureimpl) DissociateInboundRequest() {
	if !isAgentReady() {
		return
	}
	disassociate(getID())
}

func (k Secureimpl) AssociateOutboundRequest(dest, dport, urlx string) {
	//UpdateHttpConnsOut(dest, dport, urlx)
}

func (k Secureimpl) CalculateOutboundApiId() {
	request := getRequest(getID())
	if request.VulnerabilityDetails.APIID == "" {
		vulnerabilityDetails := presentStack(request.Request.Method)
		request.VulnerabilityDetails = vulnerabilityDetails
	}
}

func (k Secureimpl) GetRequest() *secUtils.Info_req {
	req, ok := requestMap.Load(getID())
	if ok && req != nil {
		return req.(*secUtils.Info_req)
	}
	return nil
}

/**
 * Implementation for gRPC frameworks
 */

func (k Secureimpl) AssociateGrpcQueryParam(body interface{}) {
	request := getRequest(getID())
	if request == nil {
		logger.Debugln("(AssociateGrpcQueryParam) GRPC Request Not Found")
		return
	}
	request.Request.IsGRPC = true
	request.GrpcBody = append(request.GrpcBody, body)
}

func (k Secureimpl) AssociateGrpcDataBytes(data []byte) bool {
	request := getRequest(getID())
	if request == nil {
		logger.Errorln("(AssociateGrpcDataBytes) GRPC Request Not Found creating new request without headers")
		return false
	}
	request.GrpcByte = append(request.GrpcByte, data)
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
		return request.RequestIdentifier
	}
}

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

func (k Secureimpl) SendEvent(category string, args interface{}) *secUtils.EventTracker {
	secConfig.AddEventDataToListener(secConfig.TestArgs{Parameters: fmt.Sprintf("%v", args), CaseType: category})
	if !isAgentReady() {
		return nil
	}
	eventId := increaseCount()
	return sendEvent(eventId, category, args)
}

func (k Secureimpl) SendExitEvent(event *secUtils.EventTracker) {
	if event == nil {
		return
	}
	if !(secConfig.GlobalInfo.CurrentPolicy.VulnerabilityScan.Enabled && secConfig.GlobalInfo.CurrentPolicy.VulnerabilityScan.IastScan.Enabled) {
		return
	}
	requestIdentifier := event.RequestIdentifier

	if !(requestIdentifier != "" && secUtils.CaseInsensitiveContains(requestIdentifier, event.APIID) && secUtils.CaseInsensitiveContains(requestIdentifier, ":IAST:VULNERABLE:IAST:")) {
		return
	}

	eventGeneration.SendExitEvent(event, requestIdentifier)
}

func sendEvent(eventId, category string, args interface{}) *secUtils.EventTracker {
	id := getID()
	req := getRequest(id)
	if !isAgentReady() || (req == nil) {
		logger.Debugln(category, "no incoming skipping Event")
		return nil
	}
	var vulnerabilityDetails secUtils.VulnerabilityDetails
	if category == "REFLECTED_XSS" && (*req).VulnerabilityDetails.APIID != "" {
		vulnerabilityDetails = (*req).VulnerabilityDetails
	} else {
		vulnerabilityDetails = presentStack((*req).Request.Method)
	}

	return eventGeneration.SendVulnerableEvent(req, category, args, vulnerabilityDetails, getEventID(eventId, id))

}

/**
 * Sync Map operations
 */

// associate request with goroutines ID
func associate(id string, a *secUtils.Info_req) {
	requestMap.Store(id, a)
}

// disassociate request with goroutines ID
func disassociate(id string) {
	requestMap.Delete(id)
}

// get Http request with goroutines ID
func getRequest(id string) *secUtils.Info_req {
	req, ok := requestMap.Load(id)
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

func presentStack(method string) (vulnerabilityDetails secUtils.VulnerabilityDetails) {
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
		if !isSecureAgentCode {
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

	vulnerabilityDetails.APIID = apiId
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
	return !strings.Contains(path, "go/src")

}

func isSecureAgentCode(name string) bool {

	if strings.Contains(name, "github.com/newrelic/go-agent") || strings.Contains(name, "github.com/newrelic/csec-go-agent") {
		return true
	}

	return false
}

func increaseCount() string {
	eventCount := atomic.LoadUint64(&secConfig.GlobalInfo.InstrumentationData.HookCalledCount)
	atomic.AddUint64(&secConfig.GlobalInfo.InstrumentationData.HookCalledCount, 1)
	return strconv.FormatUint(eventCount, 10)
}
