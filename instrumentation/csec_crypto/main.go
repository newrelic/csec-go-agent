package csec_crypto

import (
	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

func init() {
	if !secIntercept.IsAgentInitializedForHook() || secIntercept.IsForceDisable() || !secIntercept.IsHookingoIsSupported() {
		return
	}
	initSha1Hook()
	initSha3Hook()
	initSha256Hook()
	initSha512Hook()
	initmd5Hook()
	initblake2sHook()

	initAesHook()
	initRsaHook()
}
