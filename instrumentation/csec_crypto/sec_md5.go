package csec_crypto

import (
	"crypto/md5"

	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

//go:noinline
func secSum(data []byte) [md5.Size]byte {
	if secIntercept.IsDisable() {
		return secSum_s(data)
	}
	secIntercept.TraceHashOperation("MD5")
	return secSum_s(data)
}

//go:noinline
func secSum_s(data []byte) [md5.Size]byte {
	if secIntercept.IsDisable() {
		return secSum_s(data)
	}
	secIntercept.TraceHashOperation("MD5")
	return secSum_s(data)
}

func initmd5Hook() {
	e := secIntercept.HookWrap(md5.Sum, secSum, secSum_s)
	secIntercept.IsHookedLog("md5.Sum", e)
}
