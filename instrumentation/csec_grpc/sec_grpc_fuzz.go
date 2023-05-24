// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package csec_grpc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	grpccurl "github.com/fullstorydev/grpcurl"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/jhump/protoreflect/desc"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
	secevent "github.com/newrelic/csec-go-agent/security_event_generation"
	sechandler "github.com/newrelic/csec-go-agent/security_handlers"
	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var Grpccounter = true

var myclient *grpc.ClientConn
var mysclient *grpc.ClientConn

type SecGrpcFuzz struct {
}

type secGrpcHandler struct {
	method            *desc.MethodDescriptor
	methodCount       int
	reqHeaders        metadata.MD
	reqHeadersCount   int
	reqMessages       []string
	reqMessagesCount  int
	respHeaders       metadata.MD
	respHeadersCount  int
	respMessages      []string
	respTrailers      metadata.MD
	respStatus        *status.Status
	respTrailersCount int
}

func (grpcFuzz SecGrpcFuzz) ExecuteFuzzRequest(fuzzRequest *sechandler.FuzzRequrestHandler, caseType string) {
	fuzzRequestID := fmt.Sprintf("%v", fuzzRequest.Headers[secIntercept.NR_CSEC_FUZZ_REQUEST_ID])
	if Grpccounter {
		checkAndCreateconfFile()
		if len(confImportFiles) == 0 || len(confImportPaths) == 0 {
			logger.Errorln("csec_grpc_conf.json File is missing, Please add the csec_grpc_conf.json in application dir : ", confFilePath)
			logger.Errorln("Grpc Blackops is not running...")
			secevent.SendFuzzFailEvent(fuzzRequestID)
			return
		}
		if confImportFiles[0] == "" || confImportPaths[0] == "" {
			logger.Errorln("Grpc Running with Default Config, Please update the csec_grpc_conf.json in application dir : ", confFilePath)
			logger.Errorln("Grpc Blackops is not running...")
			secevent.SendFuzzFailEvent(fuzzRequestID)
			return
		}
		Grpccounter = false
	}
	var grpcBody []interface{}
	err := json.Unmarshal([]byte(fuzzRequest.Body), &grpcBody)
	if err != nil {
		logger.Errorln("error in Unmarshal Grpc Body : ", err.Error())
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
	h := &secGrpcHandler{reqMessages: finalData}
	error := rungrpc(fuzzRequest.Protocol, secConfig.GlobalInfo.ApplicationInfo.ServerIp+":"+gPort, fuzzRequest.Url, h, headers, fuzzRequest.ServerName)
	if error != nil {
		logger.Errorln("Failed fuzz req while doing : ", fuzzRequest.Url, fuzzRequest.Method, error.Error())
		secevent.SendFuzzFailEvent(fuzzRequestID)
	} else {
		logger.Infoln("Successfull fuzz req : ", fuzzRequest.Method, fuzzRequest.Url)
	}
	return
}

func rungrpc(proto string, client string, url string, h *secGrpcHandler, headers []string, sni string) error {
	var grpc_client *grpc.ClientConn
	var err error
	if proto == "https" {
		if mysclient == nil {
			grpc_client, err = grpc.Dial(client, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true, ServerName: sni})), grpc.WithBlock())
		} else {
			grpc_client = mysclient
		}
	} else {
		if mysclient == nil {
			grpc_client, err = grpc.Dial(client, grpc.WithInsecure(), grpc.WithBlock())
		} else {
			grpc_client = myclient
		}
	}
	if err != nil {
		return err
	}
	defer grpc_client.Close()
	refSource, err := grpccurl.DescriptorSourceFromProtoFiles(confImportPaths, confImportFiles...)
	if err != nil {
		return err
	}
	if len(url) > 1 && strings.HasPrefix(url, "/") {
		url = url[1:]
	}
	err = grpccurl.InvokeRpc(context.Background(), refSource, grpc_client, url, headers, h, h.getRequestData)
	logger.Errorln("rungrpc ERR : ", err)
	logger.Debugln("rungrpc Responce : ", h.respMessages)
	return err
}

func (h *secGrpcHandler) getRequestData() ([]byte, error) {
	h.reqMessagesCount++
	if h.reqMessagesCount > len(h.reqMessages) {
		return nil, io.EOF
	}
	if h.reqMessagesCount > 1 {
		time.Sleep(time.Millisecond * 50)
	}
	return []byte(h.reqMessages[h.reqMessagesCount-1]), nil
}

func (h *secGrpcHandler) OnResolveMethod(md *desc.MethodDescriptor) {
	h.methodCount++
	h.method = md
}

func (h *secGrpcHandler) OnSendHeaders(md metadata.MD) {
	h.reqHeadersCount++
	h.reqHeaders = md
}

func (h *secGrpcHandler) OnReceiveHeaders(md metadata.MD) {
	h.respHeadersCount++
	h.respHeaders = md
}

func (h *secGrpcHandler) OnReceiveResponse(msg proto.Message) {
	//TODO
	jsm := jsonpb.Marshaler{Indent: "  "}
	respStr, err := jsm.MarshalToString(msg)
	if err != nil {
		panic(fmt.Errorf("failed to generate JSON form of response message: %v", err))
	}
	h.respMessages = append(h.respMessages, respStr)
}

func (h *secGrpcHandler) OnReceiveTrailers(stat *status.Status, md metadata.MD) {
	h.respTrailersCount++
	h.respTrailers = md
	h.respStatus = stat
}
