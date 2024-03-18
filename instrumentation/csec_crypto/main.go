package csec_crypto

import (
	"crypto/sha512"

	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

//go:noinline
func secSum512_256_s(data []byte) [sha512.Size256]byte {
	if secIntercept.IsDisable() {
		return secSum512_256_s(data)
	}
	secIntercept.TraceHashOperation("SHA-256")

	return secSum512_256_s(data)
}

//go:noinline
func secSum512_256(data []byte) [sha512.Size256]byte {
	if secIntercept.IsDisable() {
		return secSum512_256_s(data)
	}
	secIntercept.TraceHashOperation("SHA-256")

	return secSum512_256_s(data)
}

//go:noinline
func secSum512_224(data []byte) [sha512.Size224]byte {
	if secIntercept.IsDisable() {
		return secSum512_224_s(data)
	}
	secIntercept.TraceHashOperation("SHA-224")

	return secSum512_224_s(data)
}

//go:noinline
func secSum512_224_s(data []byte) [sha512.Size224]byte {
	if secIntercept.IsDisable() {
		return secSum512_224_s(data)
	}
	secIntercept.TraceHashOperation("SHA-224")

	return secSum512_224_s(data)
}

//go:noinline
func secSum384(data []byte) [sha512.Size384]byte {
	if secIntercept.IsDisable() {
		return secSum384_s(data)
	}
	secIntercept.TraceHashOperation("SHA-384")

	return secSum384_s(data)
}

//go:noinline
func secSum384_s(data []byte) [sha512.Size384]byte {
	if secIntercept.IsDisable() {
		return secSum384_s(data)
	}
	secIntercept.TraceHashOperation("SHA-384")

	return secSum384_s(data)
}

//go:noinline
func secSum512(data []byte) [sha512.Size]byte {
	if secIntercept.IsDisable() {
		return secSum512_s(data)
	}
	secIntercept.TraceHashOperation("SHA-512")

	return secSum512_s(data)
}

//go:noinline
func secSum512_s(data []byte) [sha512.Size]byte {
	if secIntercept.IsDisable() {
		return secSum512_s(data)
	}
	secIntercept.TraceHashOperation("SHA-512")

	return secSum512_s(data)
}

func PluginStart() {
	e := secIntercept.HookWrap(sha512.Sum512, secSum512, secSum512_s)
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
	PluginStart_sha1()
	PluginStart_md5()
	PluginStart_sha3()
	PluginStart_blake2b()
}
