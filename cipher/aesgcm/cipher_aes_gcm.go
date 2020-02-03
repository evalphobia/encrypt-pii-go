package aesgcm

import (
	"github.com/evalphobia/hierogolyph/crypto/aesgcm"
)

type Cipher struct{}

// Encrypt encrypts plainText.
func (Cipher) Encrypt(plainText string, key []byte) (cipherText string, err error) {
	byt, err := aesgcm.Encrypt(plainText, key)
	return string(byt), err
}

// Decrypt decrypts cipherText.
func (Cipher) Decrypt(cipherText string, key []byte) (plainText string, err error) {
	byt, err := aesgcm.Decrypt([]byte(cipherText), key)
	return string(byt), err
}
