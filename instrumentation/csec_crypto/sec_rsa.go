package csec_crypto

import (
	"crypto/rsa"
	"hash"
	"io"

	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

//go:noinline
func encryptOAEP(hash hash.Hash, random io.Reader, pub *rsa.PublicKey, msg []byte, label []byte) ([]byte, error) {
	if secIntercept.IsDisable() {
		return encryptOAEP_s(hash, random, pub, msg, label)
	}
	secIntercept.TraceCryptoOperation("RSA/OAEP")

	return encryptOAEP_s(hash, random, pub, msg, label)
}

//go:noinline
func encryptOAEP_s(hash hash.Hash, random io.Reader, pub *rsa.PublicKey, msg []byte, label []byte) ([]byte, error) {
	if secIntercept.IsDisable() {
		return encryptOAEP_s(hash, random, pub, msg, label)
	}
	secIntercept.TraceCryptoOperation("RSA/OAEP")

	return encryptOAEP_s(hash, random, pub, msg, label)
}

//go:noinline
func encryptPKCS1v15(random io.Reader, pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	if secIntercept.IsDisable() {
		return encryptPKCS1v15_s(random, pub, msg)
	}
	secIntercept.TraceCryptoOperation("RSA/PKC")

	return encryptPKCS1v15_s(random, pub, msg)
}

//go:noinline
func encryptPKCS1v15_s(random io.Reader, pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	if secIntercept.IsDisable() {
		return encryptPKCS1v15_s(random, pub, msg)
	}
	secIntercept.TraceCryptoOperation("RSA/PKC")
	return encryptPKCS1v15_s(random, pub, msg)
}

func PluginStart_rsa() {
	e := secIntercept.HookWrap(rsa.EncryptOAEP, encryptOAEP, encryptOAEP_s)
	secIntercept.IsHookedLog("rsa.EncryptOAEP", e)

	e = secIntercept.HookWrap(rsa.EncryptPKCS1v15, encryptPKCS1v15, encryptPKCS1v15_s)
	secIntercept.IsHookedLog("rsa.EncryptPKCS1v15", e)
}
