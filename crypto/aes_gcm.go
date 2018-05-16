package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// EncryptByGCM encrypts plainText using AES GCM mode.
func EncryptByGCM(plainText string, key []byte) ([]byte, error) {
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

// DecryptByGCM decrypts cipherText using AES GCM mode.
func DecryptByGCM(cipherText, key []byte) (string, error) {
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

	nonce := cipherText[:gcm.NonceSize()]
	plainByte, err := gcm.Open(nil, nonce, cipherText[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}

	return string(plainByte), nil
}
