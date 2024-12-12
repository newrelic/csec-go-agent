package csec_crypto

import (
	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
	"golang.org/x/crypto/sha3"
)

//go:noinline
func secSha3Sum224(data []byte) (digest [28]byte) {
	if secIntercept.IsDisable() {
		return secSha3Sum224_s(data)
	}
	secIntercept.TraceHashOperation("SHA-224")
	return secSha3Sum224_s(data)
}

//go:noinline
func secSha3Sum224_s(data []byte) (digest [28]byte) {
	if secIntercept.IsDisable() {
		return secSha3Sum224_s(data)
	}
	secIntercept.TraceHashOperation("SHA-224")
	return secSha3Sum224_s(data)
}

//go:noinline
func secSha3Sum256(data []byte) (digest [32]byte) {
	if secIntercept.IsDisable() {
		return secSha3Sum256_s(data)
	}
	secIntercept.TraceHashOperation("SHA-256")
	return secSha3Sum256_s(data)
}

//go:noinline
func secSha3Sum256_s(data []byte) (digest [32]byte) {
	if secIntercept.IsDisable() {
		return secSha3Sum256_s(data)
	}
	secIntercept.TraceHashOperation("SHA-256")
	return secSha3Sum256_s(data)
}

//go:noinline
func secSha3Sum384(data []byte) (digest [48]byte) {
	if secIntercept.IsDisable() {
		return secSha3Sum384_s(data)
	}
	secIntercept.TraceHashOperation("SHA-384")
	return secSha3Sum384_s(data)
}

//go:noinline
func secSha3Sum384_s(data []byte) (digest [48]byte) {
	if secIntercept.IsDisable() {
		return secSha3Sum384_s(data)
	}
	secIntercept.TraceHashOperation("SHA-384")
	return secSha3Sum384_s(data)
}

//go:noinline
func secSha3Sum512(data []byte) (digest [64]byte) {
	if secIntercept.IsDisable() {
		return secSha3Sum512_s(data)
	}
	secIntercept.TraceHashOperation("SHA-512")
	return secSha3Sum512_s(data)
}

//go:noinline
func secSha3Sum512_s(data []byte) (digest [64]byte) {
	if secIntercept.IsDisable() {
		return secSha3Sum512_s(data)
	}
	secIntercept.TraceHashOperation("SHA-512")
	return secSha3Sum512_s(data)
}

func initSha3Hook() {

	e := secIntercept.HookWrap(sha3.Sum224, secSha3Sum224, secSha3Sum224_s)
	secIntercept.IsHookedLog("blake2s.Sum256", e)
	e = secIntercept.HookWrap(sha3.Sum256, secSha3Sum256, secSha3Sum256_s)
	secIntercept.IsHookedLog("sha3.Sum256", e)
	e = secIntercept.HookWrap(sha3.Sum384, secSha3Sum384, secSha3Sum384_s)
	secIntercept.IsHookedLog("sha3.Sum384", e)
	e = secIntercept.HookWrap(sha3.Sum512, secSha3Sum512, secSha3Sum512_s)
	secIntercept.IsHookedLog("sha3.Sum512", e)
}
