package aesgcm

import (
	"bytes"

	"github.com/evalphobia/hierogolyph/crypto"
)

const (
	encryptionPrefix = "GCMx"
)

// AesGcm is mock of HSM.
// It's a fake HSM and using AES CTR(GCM mode) for encryption.
type AesGcm struct {
	Key []byte
}

// NewAesGcm creates new AesGcm.
func NewAesGcm(key []byte) *AesGcm {
	// use first 32byte if the key length is longer than 32byte.
	if len(key) > 32 {
		key = key[0:32]
	}

	return &AesGcm{
		Key: key,
	}
}

// Encrypt encrypts plainText and adds prefix.
func (a *AesGcm) Encrypt(plainText string) (cipherText string, err error) {
	byt, err := crypto.EncryptByGCM(plainText, a.Key)
	return encryptionPrefix + string(byt), err
}

// Decrypt decrypts prefixed cipherByte.
func (a *AesGcm) Decrypt(cipherByte []byte) (plainText string, err error) {
	byt, err := crypto.DecryptByGCM(bytes.TrimPrefix(cipherByte, []byte(encryptionPrefix)), a.Key)
	return string(byt), err
}
