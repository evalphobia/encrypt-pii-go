package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// Encrypt encrypts plainText using AES GCM mode.
func Encrypt(plainText string, key []byte) ([]byte, error) {
	// use first 32byte if the key length is longer than 32byte.
	if len(key) > 32 {
		key = key[0:32]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	cipherText := gcm.Seal(nil, nonce, []byte(plainText), nil)
	cipherText = append(nonce, cipherText...)

	return cipherText, nil
}

// Decrypt decrypts cipherText using AES GCM mode.
func Decrypt(cipherText, key []byte) (string, error) {
	// use first 32byte if the key length is longer than 32byte.
	if len(key) > 32 {
		key = key[0:32]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return "", fmt.Errorf("cipherText is too short: textsize=[%d], noncesize=[%d]", len(cipherText), nonceSize)
	}

	nonce := cipherText[:nonceSize]
	plainByte, err := gcm.Open(nil, nonce, cipherText[nonceSize:], nil)
	if err != nil {
		return "", err
	}

	return string(plainByte), nil
}
