package security_utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	ITERATION                                     = 1024
	KEY_LEN                                       = 32 // 256 bits
	OFFSET                                        = 16
	EMPTY_PASSWORD                                = "Empty Password provided"
	DATA_TO_BE_DECRYPTED                          = "Data to be decrypted is Empty"
	INCORRECT_SECRET                              = "Incorrect Password / salt provided: %s"
	EMPTY_SECRET                                  = "secretKey is empty"
	ERROR_WHILE_DECRYPTION                        = "Error while decryption %s: %s"
	ENCRYPTED_DATA_DECRYPTED_DATA                 = "Encrypted Data: %s, Decrypted data: %s"
	ERROR_WHILE_GENERATING_REQUIRED_SALT_FROM_S_S = "Error while generating required salt from %s"
	ERROR_WHILE_VERIFY_HASH_DATA                  = "Hash Data not macth %s: %s"
)

func Decrypt(password, encryptedData, hashVerifier string) (string, error) {
	if password == "" {

		return "", fmt.Errorf(EMPTY_PASSWORD)
	}
	if encryptedData == "" {
		return "", fmt.Errorf(DATA_TO_BE_DECRYPTED)
	}

	salt, err := generateSalt(password)
	if err != nil {
		return "", fmt.Errorf(ERROR_WHILE_GENERATING_REQUIRED_SALT_FROM_S_S, err)
	}

	secretKey := deriveKey(password, salt)
	if secretKey == nil {
		return "", errors.New(EMPTY_SECRET)
	}

	encryptedBytes, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf(INCORRECT_SECRET, err)
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", fmt.Errorf(INCORRECT_SECRET, err)
	}

	decrypted := make([]byte, len(encryptedBytes))

	cipher.NewCBCDecrypter(block, make([]byte, block.BlockSize())).CryptBlocks(decrypted, encryptedBytes)
	decrypted = removePadding(decrypted)
	decryptedData := string(decrypted[OFFSET:])

	if verifyHashData(hashVerifier, decryptedData) {
		return decryptedData, nil
	} else {
		return "", fmt.Errorf(ERROR_WHILE_VERIFY_HASH_DATA, hashVerifier, decryptedData)
	}

}

func generateSalt(salt string) ([]byte, error) {
	// Encode the first OFFSET characters of the salt as hexadecimal
	if len([]byte(salt)) < OFFSET {

		return nil, errors.New("Error while generating required salt")
	}
	encoded := hex.EncodeToString([]byte(salt)[:OFFSET])

	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	return decoded, nil
}

func deriveKey(password string, salt []byte) []byte {
	key, err := pbkdf2KeyDerivation([]byte(password), salt, ITERATION, KEY_LEN)
	if err != nil {
		return nil
	}
	return key
}

func pbkdf2KeyDerivation(password, salt []byte, iterations, keyLen int) ([]byte, error) {
	key := pbkdf2.Key(password, salt, iterations, keyLen, sha1.New)
	return key, nil
}

func verifyHashData(knownDecryptedDataHash, decryptedData string) bool {
	return knownDecryptedDataHash == generateSHA256HexDigest(decryptedData)
}

func generateSHA256HexDigest(data string) string {
	digest := sha256.Sum256([]byte(data))
	return hex.EncodeToString(digest[:])
}

func removePadding(data []byte) []byte {
	if i := len(data) - 1; i > 0 {
		paddingLength := int(data[i])
		if j := len(data) - paddingLength; j > 0 {
			return data[:j]
		}
	}
	return data
}
