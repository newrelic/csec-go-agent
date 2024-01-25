// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_instrumentation

import (
	"fmt"
	"runtime"
	"runtime/debug"

	logging "github.com/newrelic/csec-go-agent/internal/security_logs"
	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

var logger = logging.GetLogger("hook")

const id = "github.com/newrelic/csec-go-agent"

var (
	constant = map[string]string{
		"github.com/go-ldap/ldap/v3":        id + "/instrumentation/csec_ldap_v3",
		"go.mongodb.org/mongo-driver/mongo": id + "/instrumentation/csec_mongodb_mongo",
		"github.com/robertkrimen/otto":      id + "/instrumentation/csec_robertkrimen_otto",
		"github.com/augustoroman/v8":        id + "/instrumentation/csec_augustoroman_v8",
		"github.com/antchfx/xpath":          id + "/instrumentation/csec_antchfx_xpath",
		"github.com/antchfx/xmlquery":       id + "/instrumentation/csec_antchfx_xmlquery",
		"github.com/antchfx/jsonquery":      id + "/instrumentation/csec_antchfx_jsonquery",
		"github.com/antchfx/htmlquery":      id + "/instrumentation/csec_antchfx_htmlquery",
		"google.golang.org/grpc":            id + "/instrumentation/csec_grpc",
		"github.com/valyala/fasthttp":       id + "/instrumentation/csec_valyala_fasthttp",
	}
)

// --------------------------------------------------------------------------
// func init - initialize package, apply hooks
// --------------------------------------------------------------------------
func init() {

	if !secIntercept.IsAgentInitializedForHook() {
		return
	}
	if secIntercept.IsForceDisable() {
		return
	}
	locateImports()
	if secIntercept.IsHookingoIsSupported() {
		secIntercept.InitSyms()
		init_hooks()
	} else {
		printlogs := fmt.Sprintf("Go Security Agent running enviroement = %s ,%s ", runtime.GOOS, runtime.GOARCH)
		secIntercept.SendLogMessage(printlogs, "security_instrumentation", "SEVERE")
	}
	initBlackops()
}

func init_hooks() {
	initServerHook()
	initSqlHook()
	initOshooks()
	initFilehooks()
	secIntercept.SetHooked()
	logging.EndStage("6", "Application instrumentation applied successfully")

}

func initBlackops() {
	secIntercept.InitHttpFuzzRestClient(SecHttpFuzz{})
}

// ----------------------------------------------------------------

// Func: locateImports
//    Check appropriate security submodules are included.

// ----------------------------------------------------------------
func locateImports() {

	buildInfo, ok := debug.ReadBuildInfo() // ReadBuildInfo returns the build information embedded in the running binary

	if buildInfo == nil || !ok {
		logger.Debugln("No import found, Please make sure binary built with module support")
		return
	}
	dependencieMap := make(map[string]string, 0)
	for _, dependencie := range buildInfo.Deps {
		dependencieMap[dependencie.Path] = dependencie.Version
	}
	for wrapper, secWrapper := range constant {
		if _, ok := dependencieMap[wrapper]; ok {
			if _, ok := dependencieMap[secWrapper]; !ok {
				printlogs := fmt.Sprintf("Warning : Your application seems to be using package %s. Please make sure you import %s package to enable security for package %s.", wrapper, secWrapper, wrapper)
				secIntercept.SendLogMessage(printlogs, "locateImports", "INFO")
				logging.PrintWarnlog(printlogs)
			}
		}
	}
}
