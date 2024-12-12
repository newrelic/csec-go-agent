// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package security_handlers

import (
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

	completedRequestIds *sync.Map
	pendingRequestIds   *sync.Map

	coolDownSleepTime          time.Time
	lastFuzzRequestTime        time.Time
	isFuzzSchedulerInitialized bool
	fuzzedApi                  sync.Map
}

func (r *RestRequestThreadPool) InitFuzzScheduler() {
	if !r.isFuzzSchedulerInitialized {
		go r.initFuzzScheduler()
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
		r.completedRequestIds = &sync.Map{}
		r.pendingRequestIds = &sync.Map{}
		if !r.threadPool.IsTaskPoolEmpty() {
			r.threadPool.Clean()
			r.threadPool = threadpool.NewThreadPool(queueSize, maxPoolSize, logger, "RestRequestThreadPool")
		}
	}
}

func (r *RestRequestThreadPool) CompletedRequestIds() interface{} {
	mapRequestIds := map[string]interface{}{}

	if r.completedRequestIds != nil {
		r.completedRequestIds.Range(func(key, value interface{}) bool {
			mapRequestIds[key.(string)] = value
			return true
		})
	}

	return mapRequestIds
}

func (r *RestRequestThreadPool) SetCompletedRequestIds(completedRequestIds *sync.Map) {
	r.completedRequestIds = completedRequestIds
}

func (r *RestRequestThreadPool) AppendCompletedRequestIds(requestId, apiId string) {
	if apiId != "" {
		result, ok := r.completedRequestIds.Load(requestId)
		if ok {
			results := result.([]string)
			results = append(results, apiId)
			r.completedRequestIds.Store(requestId, results)
		} else {
			r.completedRequestIds.Store(requestId, []string{apiId})
		}
	} else {
		r.completedRequestIds.Store(requestId, []string{})
	}
}

func (r *RestRequestThreadPool) RemoveCompletedRequestIds(requestId string) {
	r.completedRequestIds.Delete(requestId)
}

func (r *RestRequestThreadPool) SetPendingRequestIds(pendingRequestIds *sync.Map) {
	r.pendingRequestIds = pendingRequestIds
}

func (r *RestRequestThreadPool) AppendPendingRequestIds(requestId string) {
	r.pendingRequestIds.Store(requestId, 1)
}

func (r *RestRequestThreadPool) RemovePendingRequestIds(requestId string) {
	r.pendingRequestIds.Delete(requestId)
}

func (r *RestRequestThreadPool) PendingRequestIds() []string {
	keys := []string{}
	if r.pendingRequestIds != nil {
		r.pendingRequestIds.Range(func(key, value interface{}) bool {
			keys = append(keys, key.(string))
			return true
		})

	}

	return keys
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
