package csec_crypto

import (
	"crypto/aes"
	"crypto/cipher"

	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

//go:noinline
func NewCipher(key []byte) (cipher.Block, error) {
	if secIntercept.IsDisable() {
		return NewCipher_s(key)
	}
	secIntercept.TraceCryptoOperation("AES")
	return NewCipher_s(key)
}

//go:noinline
func NewCipher_s(key []byte) (cipher.Block, error) {
	if secIntercept.IsDisable() {
		return NewCipher_s(key)
	}
	secIntercept.TraceCryptoOperation("AES")
	return NewCipher_s(key)
}

func initAesHook() {
	if !secIntercept.IsAgentInitializedForHook() || secIntercept.IsForceDisable() || !secIntercept.IsHookingoIsSupported() {
		return
	}

	e := secIntercept.HookWrap(aes.NewCipher, NewCipher, NewCipher_s)
	secIntercept.IsHookedLog("aes.NewCipher", e)
}
