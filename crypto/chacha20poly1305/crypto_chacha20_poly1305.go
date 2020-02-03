package chacha20poly1305

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize    = chacha20poly1305.KeySize
	nonceSizeX = chacha20poly1305.NonceSizeX
)

// Encrypt encrypts plainText using XChaCha20-Poly1305.
func Encrypt(plainText string, key []byte) ([]byte, error) {
	// use first 32byte if the key length is longer than 32byte.
	if len(key) > KeySize {
		key = key[0:KeySize]
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	cipherText := aead.Seal(nil, nonce, []byte(plainText), nil)
	cipherText = append(nonce, cipherText...)
	return cipherText, nil
}

// Decrypt decrypts cipherText using XChaCha20-Poly1305.
func Decrypt(cipherText, key []byte) (string, error) {
	// use first 32byte if the key length is longer than 32byte.
	if len(key) > KeySize {
		key = key[0:KeySize]
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}

	if len(cipherText) < nonceSizeX {
		return "", fmt.Errorf("cipherText is too short: textsize=[%d], noncesize=[%d]", len(cipherText), nonceSizeX)
	}

	nonce := cipherText[:nonceSizeX]
	plainByte, err := aead.Open(nil, nonce, cipherText[nonceSizeX:], nil)
	if err != nil {
		return "", err
	}

	return string(plainByte), nil
}
