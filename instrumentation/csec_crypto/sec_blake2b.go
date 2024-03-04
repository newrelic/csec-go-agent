package csec_crypto

import (
	"golang.org/x/crypto/blake2s"

	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

func secBlake2sSum256(data []byte) [blake2s.Size]byte {
	if secIntercept.IsDisable() {
		return secBlake2sSum256_s(data)
	}
	secIntercept.TraceCryptoOperation("SHA-256")
	return secBlake2sSum256_s(data)
}
func secBlake2sSum256_s(data []byte) [blake2s.Size]byte {
	if secIntercept.IsDisable() {
		return secBlake2sSum256_s(data)
	}
	secIntercept.TraceCryptoOperation("SHA-256")
	return secBlake2sSum256_s(data)
}

func PluginStart_blake2b() {

	e := secIntercept.HookWrap(blake2s.Sum256, secBlake2sSum256, secBlake2sSum256_s)
	secIntercept.IsHookedLog("blake2s.Sum256", e)
}
