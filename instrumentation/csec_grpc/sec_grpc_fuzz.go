// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package csec_grpc

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
	secevent "github.com/newrelic/csec-go-agent/security_event_generation"
	sechandler "github.com/newrelic/csec-go-agent/security_handlers"
	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type SecGrpcFuzz struct {
}

func (grpcFuzz SecGrpcFuzz) ExecuteFuzzRequest(fuzzRequest *sechandler.FuzzRequrestHandler, caseType string, fuzzId string) {
	fuzzRequestID := fmt.Sprintf("%v", fuzzRequest.Headers[secIntercept.NR_CSEC_FUZZ_REQUEST_ID])
	sechandler.FuzzHandler.AppendCompletedRequestIds(fuzzId, "")
	var grpcBody []interface{}
	err := json.Unmarshal([]byte(fuzzRequest.Body), &grpcBody)
	if err != nil {
		logger.Debugln("ERROR: error in unmarshal gRPC body : ", err.Error(), fuzzRequest.Body)
		secIntercept.SendLogMessage("ERROR: error in unmarshal gRPC body : "+err.Error(), "csec_grpc")
		secevent.SendFuzzFailEvent(fuzzRequestID)
		return
	}

	data := grpcBody
	var finalData []string
	for _, value := range data {
		jsonString, _ := json.Marshal(value)
		finalData = append(finalData, string(jsonString))
	}

	var headers []string
	for key, element := range fuzzRequest.Headers {
		if !strings.HasPrefix(key, ":") && key != "content-type" {
			tmp := fmt.Sprintf("%s: %s", key, element)
			headers = append(headers, tmp)
		}

	}

	gPort := strconv.Itoa(fuzzRequest.ServerPort)

	client, err := getFuzzClient(fuzzRequest.Protocol, secConfig.GlobalInfo.ApplicationInfo.ServerIp+":"+gPort, fuzzRequest.ServerName)

	if err != nil {
		logger.Errorln("ERROR: Failed to create fuzz client : ", secConfig.GlobalInfo.ApplicationInfo.ServerIp, gPort, err.Error())
		secIntercept.SendLogMessage("ERROR: Failed to create fuzz client : "+secConfig.GlobalInfo.ApplicationInfo.ServerIp+gPort+err.Error(), "csec_grpc")
		secevent.SendFuzzFailEvent(fuzzRequestID)
	}

	url := fuzzRequest.Method
	if len(url) > 1 && strings.HasPrefix(url, "/") {
		url = url[1:]
	}

	tmp := fmt.Sprintf("%s: %s", "nr-csec-parent-id", fuzzId)
	headers = append(headers, tmp)

	h := &secGrpcHandler{
		reqMessages:        finalData,
		isClientStream:     fuzzRequest.MetaData.IsGrpcClientStream,
		isServerStream:     fuzzRequest.MetaData.IsServerStream,
		grcpMessageType:    fuzzRequest.MetaData.GrcpMessageType,
		grcpMessageVersion: fuzzRequest.MetaData.GrcpMessageVersion,
		reqheaders:         headers,
		method:             url,
	}

	error := h.invokeRpc(client)

	if error != nil {
		logger.Debugln("ERROR: Failed fuzz req while doing : ", fuzzRequest.Url, fuzzRequest.Method, error.Error())
		secevent.SendFuzzFailEvent(fuzzRequestID)
	} else {
		logger.Infoln("Successfull fuzz req : ", fuzzRequest.Method, fuzzRequest.Url)
	}

}

func getFuzzClient(protocol, url, serverName string) (*grpc.ClientConn, error) {
	if secUtils.CaseInsensitiveEquals(protocol, "https") {
		return getHttpsClient(url, serverName)
	} else {
		return getHttpClient(url)
	}
}

func getHttpClient(url string) (*grpc.ClientConn, error) {
	client, err := grpc.Dial(url, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	return client, nil
}

func getHttpsClient(url, serverName string) (*grpc.ClientConn, error) {
	client, err := grpc.Dial(url, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true, ServerName: serverName})))
	if err != nil {
		return nil, err
	}
	return client, nil
}
