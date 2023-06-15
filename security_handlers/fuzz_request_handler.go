// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_handlers

import (
	threadpool "github.com/newrelic/csec-go-agent/internal/security_threadpool"
	eventGeneration "github.com/newrelic/csec-go-agent/security_event_generation"
	"time"
)

const (
	queueSize   = 1000
	maxPoolSize = 3
)

var FuzzHandler = RestRequestThreadPool{}

type FuzzTask struct {
	fuzzRequrestHandler *FuzzRequrestHandler
	caseType            string
	requestID           string
}

func (fTask *FuzzTask) Run() {

	if fTask.fuzzRequrestHandler.IsGRPC {
		if FuzzHandler.grpsFuzzRestClient == nil {
			logger.Errorln("gRPC rest client not initialised")
		} else {
			FuzzHandler.grpsFuzzRestClient.ExecuteFuzzRequest(fTask.fuzzRequrestHandler, fTask.caseType)
			FuzzHandler.AppendCompletedRequestIds(fTask.requestID)
		}
	} else {
		if FuzzHandler.httpFuzzRestClient == nil {
			logger.Errorln("http rest client not initialised")
		} else {
			FuzzHandler.httpFuzzRestClient.ExecuteFuzzRequest(fTask.fuzzRequrestHandler, fTask.caseType)
			FuzzHandler.AppendCompletedRequestIds(fTask.requestID)
		}
	}
}

func registerFuzzTask(kcc11 *FuzzRequrestHandler, caseType, requestID string) {
	task := &FuzzTask{kcc11, caseType, requestID}
	if FuzzHandler.threadPool == nil {
		initRestRequestThreadPool()
	}
	FuzzHandler.threadPool.RegisterTask(task)
}

func removeRequestID(requestID []string) {
	if FuzzHandler.threadPool == nil {
		initRestRequestThreadPool()
	}
	for _, req := range requestID {
		FuzzHandler.RemoveCompletedRequestIds(req)
	}
}

func initRestRequestThreadPool() {
	FuzzHandler.SetCompletedRequestIds(make(map[string]int))
	FuzzHandler.threadPool = threadpool.NewThreadPool(queueSize, maxPoolSize, logger, "RestRequestThreadPool")
}

func InitFuzzScheduler() {
	if FuzzHandler.threadPool == nil {
		initRestRequestThreadPool()
	}
	eventGeneration.IASTDataRequest(200, FuzzHandler.CompletedRequestIds())
	for {
		logger.Infoln("Called test ")
		currentTime := time.Now()
		coolDownSleepTime := int64(FuzzHandler.CoolDownSleepTime().Sub(currentTime).Minutes())
		logger.Infoln("cooldownSleepTime", coolDownSleepTime)
		if coolDownSleepTime > 0 {
			time.Sleep(time.Duration(coolDownSleepTime) * time.Minute)
		}
		currentFetchThreshold := 300 //SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_PROBING_THRESHOLD
		remainingRecordCapacity := FuzzHandler.threadPool.RemainingCapacity()
		currentRecordBacklog := FuzzHandler.threadPool.PendingTask()
		batchSize := currentFetchThreshold - currentRecordBacklog
		batchSize = 200
		logger.Infoln("InitFuzzScheduler test ", batchSize, remainingRecordCapacity, currentRecordBacklog, currentFetchThreshold)

		if batchSize > 100 && remainingRecordCapacity > batchSize {
			logger.Infoln("InitFuzzScheduler", batchSize*2)
			eventGeneration.IASTDataRequest(batchSize*2, FuzzHandler.CompletedRequestIds())
		}
		time.Sleep(5 * time.Minute)
	}
}

// INFO   [14-Jun-2023 11:05:41 IST]50820:fuzz_request_handler.go:82 InitFuzzScheduler test  300 1000 0 300        logger="wsclient"
