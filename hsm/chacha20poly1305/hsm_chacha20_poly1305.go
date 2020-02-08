package chacha20poly1305

import (
	"bytes"

	"github.com/evalphobia/hierogolyph/crypto/chacha20poly1305"
)

const (
	encryptionPrefix = "ChaCha20x"
)

// MockHSM is mock of HSM.
// It's a fake HSM and using ChaCha20Poly1305 for encryption.
type MockHSM struct {
	Key []byte
}

// NewMockHSM creates new HSM.
func NewMockHSM(key []byte) *MockHSM {
	// use first 32byte if the key length is longer than 32byte.
	if len(key) > chacha20poly1305.KeySize {
		key = key[0:chacha20poly1305.KeySize]
	}

	return &MockHSM{
		Key: key,
	}
}

// Encrypt encrypts plainText and adds prefix.
func (h *MockHSM) Encrypt(plainText string) (cipherText string, err error) {
	byt, err := chacha20poly1305.Encrypt(plainText, h.Key)
	return encryptionPrefix + string(byt), err
}

// Decrypt decrypts prefixed cipherByte.
func (h *MockHSM) Decrypt(cipherByte []byte) (plainText string, err error) {
	byt, err := chacha20poly1305.Decrypt(bytes.TrimPrefix(cipherByte, []byte(encryptionPrefix)), h.Key)
	return string(byt), err
}
