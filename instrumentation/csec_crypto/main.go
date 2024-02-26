package csec_crypto

import (
	"crypto/sha512"
	"hash"

	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

//go:noinline
func secSum512_256_s(data []byte) [sha512.Size256]byte {
	if secIntercept.IsDisable() {
		return secSum512_256_s(data)
	}
	secIntercept.TraceCryptoOperation("SHA-256")

	return secSum512_256_s(data)
}

//go:noinline
func secSum512_256(data []byte) [sha512.Size256]byte {
	if secIntercept.IsDisable() {
		return secSum512_256_s(data)
	}
	secIntercept.TraceCryptoOperation("SHA-256")

	return secSum512_256_s(data)
}

//go:noinline
func secSum512_224(data []byte) [sha512.Size224]byte {
	if secIntercept.IsDisable() {
		return secSum512_224_s(data)
	}
	secIntercept.TraceCryptoOperation("SHA-224")

	return secSum512_224_s(data)
}

//go:noinline
func secSum512_224_s(data []byte) [sha512.Size224]byte {
	if secIntercept.IsDisable() {
		return secSum512_224_s(data)
	}
	secIntercept.TraceCryptoOperation("SHA-224")

	return secSum512_224_s(data)
}

//go:noinline
func secSum384(data []byte) [sha512.Size384]byte {
	if secIntercept.IsDisable() {
		return secSum384_s(data)
	}
	secIntercept.TraceCryptoOperation("SHA-384")

	return secSum384_s(data)
}

//go:noinline
func secSum384_s(data []byte) [sha512.Size384]byte {
	if secIntercept.IsDisable() {
		return secSum384_s(data)
	}
	secIntercept.TraceCryptoOperation("SHA-384")

	return secSum384_s(data)
}

//go:noinline
func secSum512(data []byte) [sha512.Size]byte {
	if secIntercept.IsDisable() {
		return secSum512_s(data)
	}
	secIntercept.TraceCryptoOperation("SHA-512")

	return secSum512_s(data)
}

//go:noinline
func secSum512_s(data []byte) [sha512.Size]byte {
	if secIntercept.IsDisable() {
		return secSum512_s(data)
	}
	secIntercept.TraceCryptoOperation("SHA-512")

	return secSum512_s(data)
}

//go:noinline
func secNew() hash.Hash {
	if secIntercept.IsDisable() {
		return secNew_s()
	}
	secIntercept.TraceCryptoOperation("SHA-512")

	return secNew_s()
}

//go:noinline
func secNew_s() hash.Hash {
	if secIntercept.IsDisable() {
		return secNew_s()
	}
	secIntercept.TraceCryptoOperation("SHA-512")

	return secNew_s()
}

//go:noinline
func secNew512_224() hash.Hash {
	if secIntercept.IsDisable() {
		return secNew512_224_s()
	}
	secIntercept.TraceCryptoOperation("SHA-224")

	return secNew512_224_s()
}

//go:noinline
func secNew512_224_s() hash.Hash {
	if secIntercept.IsDisable() {
		return secNew512_224_s()
	}
	secIntercept.TraceCryptoOperation("SHA-224")

	return secNew512_224_s()
}

//go:noinline
func secNew512_256() hash.Hash {
	if secIntercept.IsDisable() {
		return secNew512_256_s()
	}
	secIntercept.TraceCryptoOperation("SHA-256")

	return secNew512_256_s()
}

//go:noinline
func secNew512_256_s() hash.Hash {
	if secIntercept.IsDisable() {
		return secNew512_256_s()
	}
	secIntercept.TraceCryptoOperation("SHA-256")

	return secNew512_256_s()
}

//go:noinline
func secNew384() hash.Hash {
	if secIntercept.IsDisable() {
		return secNew384_s()
	}
	secIntercept.TraceCryptoOperation("SHA-384")

	return secNew384_s()
}

//go:noinline
func secNew384_s() hash.Hash {
	if secIntercept.IsDisable() {
		return secNew384_s()
	}
	secIntercept.TraceCryptoOperation("SHA-384")

	return secNew384_s()
}

func PluginStart() {

	e := secIntercept.HookWrap(sha512.New, secNew, secNew_s)
	secIntercept.IsHookedLog("sha512.New", e)
	e = secIntercept.HookWrap(sha512.New512_224, secNew512_224, secNew512_224_s)
	secIntercept.IsHookedLog("sha512.New512_224", e)
	e = secIntercept.HookWrap(sha512.New512_256, secNew512_256, secNew512_256_s)
	secIntercept.IsHookedLog("sha512.New512_256", e)
	e = secIntercept.HookWrap(sha512.New384, secNew384, secNew384_s)
	secIntercept.IsHookedLog("sha512.New384", e)

	e = secIntercept.HookWrap(sha512.Sum512, secSum512, secSum512_s)
	secIntercept.IsHookedLog("sha512.Sum512", e)
	e = secIntercept.HookWrap(sha512.Sum384, secSum384, secSum384_s)
	secIntercept.IsHookedLog("sha512.Sum384", e)
	e = secIntercept.HookWrap(sha512.Sum512_224, secSum512_224, secSum512_224_s)
	secIntercept.IsHookedLog("sha512.Sum512_224", e)
	e = secIntercept.HookWrap(sha512.Sum512_256, secSum512_256, secSum512_256_s)
	secIntercept.IsHookedLog("sha512.Sum512_256", e)
}
func init() {
	if !secIntercept.IsAgentInitializedForHook() || secIntercept.IsForceDisable() || !secIntercept.IsHookingoIsSupported() {
		return
	}
	PluginStart()
	initSha256Hook()
}
