// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_handlers

import (
	"fmt"
	"strings"
	"sync"

	threadpool "github.com/newrelic/csec-go-agent/internal/security_threadpool"
)

const (
	queueSize   = 10000
	maxPoolSize = 3
)

var FuzzHandler = RestRequestThreadPool{fuzzedApi: sync.Map{}}

type FuzzTask struct {
	fuzzRequrestHandler *FuzzRequrestHandler
	caseType            string
}

func (fTask *FuzzTask) Run() {

	if fTask.fuzzRequrestHandler.IsGRPC {
		if FuzzHandler.grpsFuzzRestClient == nil {
			logger.Errorln("gRPC rest client not initialised")
		} else {
			FuzzHandler.grpsFuzzRestClient.ExecuteFuzzRequest(fTask.fuzzRequrestHandler, fTask.caseType)
		}
	} else {
		if FuzzHandler.httpFuzzRestClient == nil {
			logger.Errorln("http rest client not initialised")
		} else {
			FuzzHandler.httpFuzzRestClient.ExecuteFuzzRequest(fTask.fuzzRequrestHandler, fTask.caseType)
		}
	}
}

func registerFuzzTask(kcc11 *FuzzRequrestHandler, caseType string) {
	task := &FuzzTask{kcc11, caseType}

	id := kcc11.Headers["nr-csec-fuzz-request-id"]
	ids := strings.Split(id.(string), ":")
	if len(ids) > 1 && !FuzzHandler.isApiIdFuzzed(ids[0]) {
		printlogs := fmt.Sprintf("IAST Scan for API %s with ID : %s started.", kcc11.RequestURI, ids[0])
		logger.Infoln(printlogs)
	}

	if FuzzHandler.threadPool != nil {
		FuzzHandler.threadPool.RegisterTask(task)
	}
}

func initRestRequestThreadPool() {
	FuzzHandler.threadPool = threadpool.NewThreadPool(queueSize, maxPoolSize, logger, "RestRequestThreadPool")
}
