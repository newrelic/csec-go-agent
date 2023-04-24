// Copyright 2022 New Relic Corporation. All rights reserved.

package security_handlers

import threadpool "github.com/newrelic/csec-go-agent/internal/security_threadpool"

const (
	queueSize   = 10000
	maxPoolSize = 3
)

var FuzzHandler = RestRequestThreadPool{}

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
	if FuzzHandler.threadPool != nil {
		FuzzHandler.threadPool.RegisterTask(task)
	}
}

func initRestRequestThreadPool() {
	FuzzHandler.threadPool = threadpool.NewThreadPool(queueSize, maxPoolSize, logger, "RestRequestThreadPool")
}
