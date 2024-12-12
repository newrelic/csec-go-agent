package csec_crypto

import (
	"crypto/sha256"

	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

//go:noinline
func secSum224(data []byte) [sha256.Size224]byte {
	if secIntercept.IsDisable() {
		return secSum224_s(data)
	}
	secIntercept.TraceHashOperation("SHA-224")

	return secSum224_s(data)
}

//go:noinline
func secSum224_s(data []byte) [sha256.Size224]byte {
	if secIntercept.IsDisable() {
		return secSum224_s(data)
	}
	secIntercept.TraceHashOperation("SHA-224")

	return secSum224_s(data)
}

//go:noinline
func secSum256(data []byte) [sha256.Size]byte {
	if secIntercept.IsDisable() {
		return secSum256_s(data)
	}
	secIntercept.TraceHashOperation("SHA-256")

	return secSum256_s(data)
}

//go:noinline
func secSum256_s(data []byte) [sha256.Size]byte {
	if secIntercept.IsDisable() {
		return secSum256_s(data)
	}
	secIntercept.TraceHashOperation("SHA-256")

	return secSum256_s(data)
}

func initSha256Hook() {
	e := secIntercept.HookWrap(sha256.Sum224, secSum224, secSum224_s)
	secIntercept.IsHookedLog("sha256.Sum224", e)
	e = secIntercept.HookWrap(sha256.Sum256, secSum256, secSum256_s)
	secIntercept.IsHookedLog("sha256.Sum256", e)
}
