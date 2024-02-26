package csec_crypto

import (
	"crypto/sha1"
	"hash"

	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

//go:noinline
func secNew1() hash.Hash {
	if secIntercept.IsDisable() {
		return secNew1_s()
	}
	secIntercept.TraceCryptoOperation("SHA-1")

	return secNew1_s()
}

//go:noinline
func secNew1_s() hash.Hash {
	if secIntercept.IsDisable() {
		return secNew1_s()
	}
	secIntercept.TraceCryptoOperation("SHA-1")

	return secNew1_s()
}

//go:noinline
func secSum1(data []byte) [sha1.Size]byte {
	if secIntercept.IsDisable() {
		return secSum1_s(data)
	}
	secIntercept.TraceCryptoOperation("SHA-1")

	return secSum1_s(data)
}

//go:noinline
func secSum1_s(data []byte) [sha1.Size]byte {
	if secIntercept.IsDisable() {
		return secSum1_s(data)
	}
	secIntercept.TraceCryptoOperation("SHA-1")

	return secSum1_s(data)
}

func PluginStart_sha1() {

	e := secIntercept.HookWrap(sha1.New, secNew1, secNew1_s)
	secIntercept.IsHookedLog("sha1.New", e)

	e = secIntercept.HookWrap(sha1.Sum, secSum1, secSum1_s)
	secIntercept.IsHookedLog("sha1.Sum", e)
}
