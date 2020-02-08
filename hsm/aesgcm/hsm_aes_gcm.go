package aesgcm

import (
	"bytes"

	"github.com/evalphobia/hierogolyph/crypto/aesgcm"
)

const (
	encryptionPrefix = "GCMx"
)

// MockHSM is mock of HSM.
// It's a fake HSM and using AES CTR(GCM mode) for encryption.
type MockHSM struct {
	Key []byte
}

// NewMockHSM creates new MockHSM.
func NewMockHSM(key []byte) *MockHSM {
	// use first 32byte if the key length is longer than 32byte.
	if len(key) > 32 {
		key = key[0:32]
	}

	return &MockHSM{
		Key: key,
	}
}

// Encrypt encrypts plainText and adds prefix.
func (h *MockHSM) Encrypt(plainText string) (cipherText string, err error) {
	byt, err := aesgcm.Encrypt(plainText, h.Key)
	return encryptionPrefix + string(byt), err
}

// Decrypt decrypts prefixed cipherByte.
func (h *MockHSM) Decrypt(cipherByte []byte) (plainText string, err error) {
	byt, err := aesgcm.Decrypt(bytes.TrimPrefix(cipherByte, []byte(encryptionPrefix)), h.Key)
	return string(byt), err
}
