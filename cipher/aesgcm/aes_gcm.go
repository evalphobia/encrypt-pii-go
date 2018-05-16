package aesgcm

import (
	"github.com/evalphobia/hierogolyph/crypto"
)

type CipherGCM struct{}

// Encrypt encrypts plainText.
func (CipherGCM) Encrypt(plainText string, key []byte) (cipherText string, err error) {
	byt, err := crypto.EncryptByGCM(plainText, key)
	return string(byt), err
}

// Decrypt decrypts cipherText.
func (CipherGCM) Decrypt(cipherText string, key []byte) (plainText string, err error) {
	byt, err := crypto.DecryptByGCM([]byte(cipherText), key)
	return string(byt), err
}
