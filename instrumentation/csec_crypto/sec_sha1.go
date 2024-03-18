package csec_crypto

import (
	"crypto/sha1"

	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

//go:noinline
func secSum1(data []byte) [sha1.Size]byte {
	if secIntercept.IsDisable() {
		return secSum1_s(data)
	}
	secIntercept.TraceHashOperation("SHA-1")

	return secSum1_s(data)
}

//go:noinline
func secSum1_s(data []byte) [sha1.Size]byte {
	if secIntercept.IsDisable() {
		return secSum1_s(data)
	}
	secIntercept.TraceHashOperation("SHA-1")

	return secSum1_s(data)
}

func PluginStart_sha1() {

	e := secIntercept.HookWrap(sha1.Sum, secSum1, secSum1_s)
	secIntercept.IsHookedLog("sha1.Sum", e)
}
