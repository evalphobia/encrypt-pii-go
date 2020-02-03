package aesgcm

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCipher(t *testing.T) {
	a := assert.New(t)
	validKey := "12345678901234567890123456789012" // 32byte
	invalidKey := "X2345678901234567890123456789012"
	shortKey := "too short"
	longKey := validKey + "XYZ" // 35byte

	tests := []struct {
		text string
	}{
		{"a"},
		{"aaa"},
		{"あいうえお"},
		{""},
	}

	c := Cipher{}
	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)

		_, err := c.Encrypt(tt.text, []byte(shortKey))
		if a.Error(err, "using short key") {
			a.Contains(err.Error(), "crypto/aes: invalid key size ", target, "using short key")
		}

		// encryption
		cipher1, err := c.Encrypt(tt.text, []byte(validKey))
		a.NoError(err, target)

		cipher2, err := c.Encrypt(tt.text, []byte(invalidKey))
		a.NoError(err, target)
		a.NotEqual(cipher1, cipher2, target, "using invalid key")

		// decryption
		plainText1, err := c.Decrypt(cipher1, []byte(validKey))
		a.NoError(err, target)
		a.Equal(tt.text, plainText1, target)

		_, err = c.Decrypt(cipher1, []byte(invalidKey))
		if a.Error(err, target) {
			a.Contains(err.Error(), "cipher: message authentication failed", target)
		}

		// long key should be used as first 32byte key.
		plainTextLongKey, err := c.Decrypt(cipher1, []byte(longKey))
		a.NoError(err, target)
		a.Equal(tt.text, plainTextLongKey, target)

		plainText2, err := c.Decrypt(cipher2, []byte(invalidKey))
		a.NoError(err, target)
		a.Equal(tt.text, plainText2, target)
	}
}
