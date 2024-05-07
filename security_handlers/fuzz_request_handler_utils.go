// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package security_handlers

import (
	"fmt"
	"sync"
	"time"

	threadpool "github.com/newrelic/csec-go-agent/internal/security_threadpool"
	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
)

type SecureFuzz interface {
	ExecuteFuzzRequest(*FuzzRequrestHandler, string, string)
}

type RestRequestThreadPool struct {
	httpFuzzRestClient SecureFuzz
	grpsFuzzRestClient SecureFuzz
	threadPool         *threadpool.ThreadPool

	pendingRequestIds *sync.Map

	completedReplay  *sync.Map
	errorInReplay    *sync.Map
	clearFromPending *sync.Map
	generatedEvents  *sync.Map

	coolDownSleepTime          time.Time
	lastFuzzRequestTime        time.Time
	isFuzzSchedulerInitialized bool
	fuzzedApi                  sync.Map
}

func (r *RestRequestThreadPool) InitFuzzScheduler() {
	if !r.isFuzzSchedulerInitialized {
		go InitFuzzScheduler()
		r.isFuzzSchedulerInitialized = true
	}
}

func (r *RestRequestThreadPool) LastFuzzRequestTime() time.Time {
	return r.lastFuzzRequestTime
}

func (r *RestRequestThreadPool) SetLastFuzzRequestTime() {
	r.lastFuzzRequestTime = time.Now()
}

func (r *RestRequestThreadPool) CoolDownSleepTime() time.Time {
	return r.coolDownSleepTime
}

func (r *RestRequestThreadPool) SetCoolDownSleepTime(coolDownSleepTimeInSecond int) {
	coolDownSleepTime := time.Now().Add(time.Duration(coolDownSleepTimeInSecond) * time.Second)
	r.coolDownSleepTime = coolDownSleepTime
}

func (r *RestRequestThreadPool) IASTCleanUp() {
	if r.threadPool != nil {
		r.completedReplay = &sync.Map{}
		r.pendingRequestIds = &sync.Map{}
		if !r.threadPool.IsTaskPoolEmpty() {
			r.threadPool.Clean()
			r.threadPool = threadpool.NewThreadPool(queueSize, maxPoolSize, logger, "RestRequestThreadPool")
		}
	}
}

func (r *RestRequestThreadPool) CompletedReplayIds() []string {
	keys := []string{}
	if r.completedReplay != nil {
		r.completedReplay.Range(func(key, value interface{}) bool {
			keys = append(keys, key.(string))
			return true
		})

	}
	return keys
}

func (r *RestRequestThreadPool) SetCompletedReplayIds(completedReplayIds *sync.Map) {
	r.completedReplay = completedReplayIds
}

func (r *RestRequestThreadPool) AppendCompletedReplayIds(requestId string) {
	r.completedReplay.Store(requestId, 1)
}

func (r *RestRequestThreadPool) RemoveCompletedRequestIds(requestId string) {
	r.completedReplay.Delete(requestId)
}

func (r *RestRequestThreadPool) SetErrorInReplayIds(errorInReplayids *sync.Map) {
	r.errorInReplay = errorInReplayids
}

func (r *RestRequestThreadPool) AppendErrorInReplayIds(requestId string) {
	r.errorInReplay.Store(requestId, 1)
}

func (r *RestRequestThreadPool) RemoveErrorInReplayIds(requestId string) {
	r.errorInReplay.Delete(requestId)
}

func (r *RestRequestThreadPool) ErrorInReplayIds() []string {
	keys := []string{}
	if r.errorInReplay != nil {
		r.errorInReplay.Range(func(key, value interface{}) bool {
			keys = append(keys, key.(string))
			return true
		})

	}
	return keys
}

func (r *RestRequestThreadPool) SetClearFromPendingIds(clearFromPending *sync.Map) {
	r.clearFromPending = clearFromPending
}

func (r *RestRequestThreadPool) AppendClearFromPendingIds(requestId string) {
	r.clearFromPending.Store(requestId, 1)
}

func (r *RestRequestThreadPool) RemoveClearFromPendingIds(requestId string) {
	r.clearFromPending.Delete(requestId)
}

func (r *RestRequestThreadPool) ClearFromPendingIds() []string {
	keys := []string{}
	if r.clearFromPending != nil {
		r.clearFromPending.Range(func(key, value interface{}) bool {
			keys = append(keys, key.(string))
			return true
		})

	}
	return keys
}

func (r *RestRequestThreadPool) SetGeneratedEventsIds(generatedEvents *sync.Map) {
	r.generatedEvents = generatedEvents
}

func (r *RestRequestThreadPool) AppendGeneratedEventsIds(appUUID, parentId, eventID string) {
	generatedEvent, ok := r.generatedEvents.Load(appUUID)
	var originMap = map[string][]string{}

	if !ok {
		r.generatedEvents.Store(appUUID, originMap)
	} else {
		tmpOriginMap, ok1 := generatedEvent.(map[string][]string)
		if ok1 {
			originMap = tmpOriginMap
		}

	}
	t := []string{}
	t = append(t, eventID)
	originMap[parentId] = t

}

func (r *RestRequestThreadPool) GeneratedEventsIds() interface{} {
	generatedEventsIds := make(map[string]interface{})
	r.generatedEvents.Range(func(k interface{}, v interface{}) bool {
		generatedEventsIds[k.(string)] = v
		return true

	})
	fmt.Println(r.generatedEvents)
	return generatedEventsIds
}

func (r *RestRequestThreadPool) RemoveGeneratedEventsIds(requestId map[string]map[string][]string) {
	for k, v := range requestId {
		generatedEvent, ok := r.generatedEvents.Load(k)
		mapa, ok1 := generatedEvent.(map[string][]string)
		if ok && ok1 {
			for k1 := range v {
				delete(mapa, k1)
			}
		}
		if len(mapa) == 0 {
			r.generatedEvents.Delete(k)
		}
	}
}

func (r *RestRequestThreadPool) InitHttpFuzzRestClient(rest SecureFuzz) {
	r.httpFuzzRestClient = rest
}

func (r *RestRequestThreadPool) InitGrpsFuzzRestClient(rest SecureFuzz) {
	r.grpsFuzzRestClient = rest

}

func (r *RestRequestThreadPool) isApiIdFuzzed(apiID interface{}) bool {
	data, ok := r.fuzzedApi.Load(apiID)
	if ok && data != nil {
		return true
	} else {
		r.fuzzedApi.Store(apiID, "")
		return false
	}
}

type FuzzRequrestHandler struct {
	QueryString      string                 `json:"queryString"`
	ClientIP         string                 `json:"clientIP"`
	ClientPort       string                 `json:"clientPort"`
	DataTruncated    bool                   `json:"dataTruncated"`
	ContentType      string                 `json:"contentType"`
	RequestURI       string                 `json:"requestURI"`
	GenerationTime   int64                  `json:"generationTime"`
	Body             string                 `json:"body"`
	Method           string                 `json:"method"`
	Url              string                 `json:"url"`
	Headers          map[string]interface{} `json:"headers"`
	WhitelistedIPs   []string               `json:"whitelistedIPs"`
	ContextPath      string                 `json:"contextPath"`
	PathParams       string                 `json:"pathParams"`
	Protocol         string                 `json:"protocol"`
	Parts            string                 `json:"parts"`
	ServerPort       int                    `json:"serverPort"`
	PathParameterMap map[string]interface{} `json:"pathParameterMap"`
	ParameterMap     map[string]interface{} `json:"parameterMap"`
	IsGRPC           bool                   `json:"isGrpc"`
	ServerName       string                 `json:"serverName"`
	MetaData         secUtils.ReflectedMetaData
}
