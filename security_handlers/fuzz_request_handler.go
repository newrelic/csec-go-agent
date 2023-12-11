// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_handlers

import (
	"fmt"
	"strings"
	"sync"
	"time"

	threadpool "github.com/newrelic/csec-go-agent/internal/security_threadpool"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
	eventGeneration "github.com/newrelic/csec-go-agent/security_event_generation"
)

const (
	queueSize   = 1000
	maxPoolSize = 3
)

var FuzzHandler = RestRequestThreadPool{fuzzedApi: sync.Map{}}

type FuzzTask struct {
	fuzzRequrestHandler *FuzzRequrestHandler
	caseType            string
	requestID           string
}

func (fTask *FuzzTask) Run() {

	if !secConfig.SecureWS.GetStatus() {
		logger.Infoln("WS not connected drop FuzzTask ")
	}

	if fTask.fuzzRequrestHandler.IsGRPC {
		if FuzzHandler.grpsFuzzRestClient == nil {
			eventGeneration.SendLogMessage("gRPC rest client not initialised", "security_handlers")
			logger.Errorln("gRPC rest client not initialised")
		} else {
			FuzzHandler.grpsFuzzRestClient.ExecuteFuzzRequest(fTask.fuzzRequrestHandler, fTask.caseType, fTask.requestID)
			FuzzHandler.RemovePendingRequestIds(fTask.requestID)
		}
	} else {
		if FuzzHandler.httpFuzzRestClient == nil {
			eventGeneration.SendLogMessage("http rest client not initialised", "security_handlers")
			logger.Errorln("http rest client not initialised")
		} else {
			FuzzHandler.httpFuzzRestClient.ExecuteFuzzRequest(fTask.fuzzRequrestHandler, fTask.caseType, fTask.requestID)
			FuzzHandler.RemovePendingRequestIds(fTask.requestID)
		}
	}
}

func registerFuzzTask(kcc11 *FuzzRequrestHandler, caseType, requestID string) {
	task := &FuzzTask{kcc11, caseType, requestID}
	if FuzzHandler.threadPool == nil {
		initRestRequestThreadPool()
	}
	id := kcc11.Headers["nr-csec-fuzz-request-id"]
	ids := strings.Split(id.(string), ":")
	if len(ids) > 1 && !FuzzHandler.isApiIdFuzzed(ids[0]) {
		printlogs := fmt.Sprintf("IAST Scan for API %s with ID : %s started.", kcc11.RequestURI, ids[0])
		logger.Infoln(printlogs)
	}
	FuzzHandler.AppendPendingRequestIds(requestID)
	FuzzHandler.threadPool.RegisterTask(task)
	FuzzHandler.SetLastFuzzRequestTime()
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
	FuzzHandler.SetCompletedRequestIds(&sync.Map{})
	FuzzHandler.SetPendingRequestIds(&sync.Map{})
	FuzzHandler.threadPool = threadpool.NewThreadPool(queueSize, maxPoolSize, logger, "RestRequestThreadPool")
}

func InitFuzzScheduler() {
	if !secConfig.GlobalInfo.IsIASTEnable() {
		return
	}
	if FuzzHandler.threadPool == nil {
		initRestRequestThreadPool()
	}
	for {
		time.Sleep(1 * time.Second)
		if !secConfig.SecureWS.GetStatus() {
			logger.Debugln("WS not connected sleep FuzzScheduler for 5 sec")
			time.Sleep(5 * time.Second)
			continue
		}
		currentTime := time.Now()
		coolDownSleepTime := int64(FuzzHandler.CoolDownSleepTime().Sub(currentTime).Seconds())
		if coolDownSleepTime > 0 {
			logger.Debugln("coolDown SleepTime", coolDownSleepTime)
			time.Sleep(time.Duration(coolDownSleepTime) * time.Second)
		}
		currentTime = time.Now()

		if currentTime.Sub(FuzzHandler.LastFuzzRequestTime()).Seconds() < 5 {
			//logger.Debugln("LastFuzzRequestTime", FuzzHandler.LastFuzzRequestTime(), currentTime)
			continue
		}

		currentFetchThreshold := 300 //SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_PROBING_THRESHOLD
		remainingRecordCapacity := FuzzHandler.threadPool.RemainingCapacity()
		currentRecordBacklog := FuzzHandler.threadPool.PendingTask()
		batchSize := currentFetchThreshold - currentRecordBacklog
		logger.Debugln("InitFuzzScheduler test ", batchSize, remainingRecordCapacity, currentRecordBacklog, currentFetchThreshold)

		if batchSize > 100 && remainingRecordCapacity > batchSize {
			logger.Debugln("InitFuzzScheduler", batchSize*2)
			eventGeneration.IASTDataRequest(batchSize*2, FuzzHandler.CompletedRequestIds(), FuzzHandler.PendingRequestIds())
		}
	}
}
