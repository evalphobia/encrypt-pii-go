package chacha20poly1305

import (
	"github.com/evalphobia/hierogolyph/crypto/chacha20poly1305"
)

type Cipher struct{}

// Encrypt encrypts plainText.
func (Cipher) Encrypt(plainText string, key []byte) (cipherText string, err error) {
	byt, err := chacha20poly1305.Encrypt(plainText, key)
	return string(byt), err
}

// Decrypt decrypts cipherText.
func (Cipher) Decrypt(cipherText string, key []byte) (plainText string, err error) {
	byt, err := chacha20poly1305.Decrypt([]byte(cipherText), key)
	return string(byt), err
}
