package csec_crypto

import (
	"crypto/aes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	secConfig "github.com/newrelic/csec-go-agent/security_config"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"
)

const CSEC_GO_AGENT = "csec-go-agent"

func TestSum512_256Hook(t *testing.T) {
	secConfig.RegisterListener()

	sha512.Sum512_256([]byte(CSEC_GO_AGENT))

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[SHA-256]", CaseType: secConfig.HASH},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestSum384Hook(t *testing.T) {
	secConfig.RegisterListener()

	sha512.Sum384([]byte(CSEC_GO_AGENT))

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[SHA-384]", CaseType: secConfig.HASH},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestSum512Hook(t *testing.T) {
	secConfig.RegisterListener()

	sha512.Sum512([]byte(CSEC_GO_AGENT))

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[SHA-512]", CaseType: secConfig.HASH},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestSum512_224Hook(t *testing.T) {
	secConfig.RegisterListener()

	sha512.Sum512_224([]byte(CSEC_GO_AGENT))

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[SHA-224]", CaseType: secConfig.HASH},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestBlake2s_Sum256Hook(t *testing.T) {
	secConfig.RegisterListener()

	blake2s.Sum256([]byte(CSEC_GO_AGENT))

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[SHA-256]", CaseType: secConfig.HASH},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestMd5_SumHook(t *testing.T) {
	secConfig.RegisterListener()

	md5.Sum([]byte(CSEC_GO_AGENT))

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[MD5]", CaseType: secConfig.HASH},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestSha1_SumHook(t *testing.T) {
	secConfig.RegisterListener()

	sha1.Sum([]byte(CSEC_GO_AGENT))

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[SHA-1]", CaseType: secConfig.HASH},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestSha3_Sum224Hook(t *testing.T) {
	secConfig.RegisterListener()

	sha3.Sum224([]byte(CSEC_GO_AGENT))

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[SHA-224]", CaseType: secConfig.HASH},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestSha3_Sum256Hook(t *testing.T) {
	secConfig.RegisterListener()

	sha3.Sum256([]byte(CSEC_GO_AGENT))

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[SHA-256]", CaseType: secConfig.HASH},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestSha3_Sum384Hook(t *testing.T) {
	secConfig.RegisterListener()

	sha3.Sum384([]byte(CSEC_GO_AGENT))

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[SHA-384]", CaseType: secConfig.HASH},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestSha3_Sum512Hook(t *testing.T) {
	secConfig.RegisterListener()

	sha3.Sum512([]byte(CSEC_GO_AGENT))

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[SHA-512]", CaseType: secConfig.HASH},
	}
	secConfig.ValidateResult(expectedData, t)
}

//

func TestSha256_Sum224Hook(t *testing.T) {
	secConfig.RegisterListener()

	sha256.Sum224([]byte(CSEC_GO_AGENT))

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[SHA-224]", CaseType: secConfig.HASH},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestSha256_Sum256Hook(t *testing.T) {
	secConfig.RegisterListener()

	sha256.Sum256([]byte(CSEC_GO_AGENT))

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[SHA-256]", CaseType: secConfig.HASH},
	}
	secConfig.ValidateResult(expectedData, t)
}

func Test_Aes_NewCipherHook(t *testing.T) {
	secConfig.RegisterListener()

	aes.NewCipher([]byte(CSEC_GO_AGENT))

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[AES]", CaseType: secConfig.CRYPTO},
	}
	secConfig.ValidateResult(expectedData, t)
}

func Test_RSA_EncryptOAEP(t *testing.T) {
	secConfig.RegisterListener()

	label := []byte(CSEC_GO_AGENT)
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey
	rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, []byte(CSEC_GO_AGENT), label)
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[RSA]", CaseType: secConfig.CRYPTO},
	}
	secConfig.ValidateResult(expectedData, t)

}

func Test_RSA_EncryptPKCS1v15(t *testing.T) {
	secConfig.RegisterListener()
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey
	rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(CSEC_GO_AGENT))

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[RSA/ECB/PKCS1Padding]", CaseType: secConfig.CRYPTO},
	}
	secConfig.ValidateResult(expectedData, t)

}
