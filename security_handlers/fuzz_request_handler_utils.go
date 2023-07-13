// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_handlers

import (
	"sync"

	threadpool "github.com/newrelic/csec-go-agent/internal/security_threadpool"
)

type SecureFuzz interface {
	ExecuteFuzzRequest(*FuzzRequrestHandler, string)
}

type RestRequestThreadPool struct {
	httpFuzzRestClient SecureFuzz
	grpsFuzzRestClient SecureFuzz
	threadPool         *threadpool.ThreadPool
	fuzzedApi          sync.Map
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
}
