package csec_crypto

import (
	"crypto/sha256"
	"hash"

	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

//go:noinline
func secNew256() hash.Hash {
	if secIntercept.IsDisable() {
		return secNew256_s()
	}
	secIntercept.TraceCryptoOperation("SHA-256")

	return secNew256_s()
}

//go:noinline
func secNew256_s() hash.Hash {
	if secIntercept.IsDisable() {
		return secNew256_s()
	}
	secIntercept.TraceCryptoOperation("SHA-256")

	return secNew256_s()
}

//go:noinline
func secNew224() hash.Hash {
	if secIntercept.IsDisable() {
		return secNew224_s()
	}
	secIntercept.TraceCryptoOperation("SHA-224")

	return secNew224_s()
}

//go:noinline
func secNew224_s() hash.Hash {
	if secIntercept.IsDisable() {
		return secNew224_s()
	}
	secIntercept.TraceCryptoOperation("SHA-224")

	return secNew224_s()
}

//go:noinline
func secSum224(data []byte) [sha256.Size224]byte {
	if secIntercept.IsDisable() {
		return secSum224_s(data)
	}
	secIntercept.TraceCryptoOperation("SHA-224")

	return secSum224_s(data)
}

//go:noinline
func secSum224_s(data []byte) [sha256.Size224]byte {
	if secIntercept.IsDisable() {
		return secSum224_s(data)
	}
	secIntercept.TraceCryptoOperation("SHA-224")

	return secSum224_s(data)
}

//go:noinline
func secSum256(data []byte) [sha256.Size]byte {
	if secIntercept.IsDisable() {
		return secSum256_s(data)
	}
	secIntercept.TraceCryptoOperation("SHA-256")

	return secSum256_s(data)
}

//go:noinline
func secSum256_s(data []byte) [sha256.Size]byte {
	if secIntercept.IsDisable() {
		return secSum256_s(data)
	}
	secIntercept.TraceCryptoOperation("SHA-256")

	return secSum256_s(data)
}

func PluginStart() {

	e := secIntercept.HookWrap(sha256.New, secNew256, secNew256_s)
	secIntercept.IsHookedLog("sha512.Sum512", e)
	e = secIntercept.HookWrap(sha256.New224, secNew224, secNew224_s)
	secIntercept.IsHookedLog("sha512.Sum384", e)

	e = secIntercept.HookWrap(sha256.Sum224, secSum224, secSum224_s)
	secIntercept.IsHookedLog("sha512.Sum512", e)
	e = secIntercept.HookWrap(sha256.Sum256, secSum256, secSum256_s)

}
