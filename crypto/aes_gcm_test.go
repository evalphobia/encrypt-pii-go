package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGCM(t *testing.T) {
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

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)

		_, err := EncryptByGCM(tt.text, []byte(shortKey))
		if a.Error(err, "using short key") {
			a.Contains(err.Error(), "crypto/aes: invalid key size ", target, "using short key")
		}

		// encryption
		cipher1, err := EncryptByGCM(tt.text, []byte(validKey))
		a.NoError(err, target)

		cipher2, err := EncryptByGCM(tt.text, []byte(invalidKey))
		a.NoError(err, target)
		a.NotEqual(cipher1, cipher2, target, "using invalid key")

		// decryption
		plainText1, err := DecryptByGCM(cipher1, []byte(validKey))
		a.NoError(err, target)
		a.Equal(tt.text, plainText1, target)

		_, err = DecryptByGCM(cipher1, []byte(invalidKey))
		if a.Error(err, target) {
			a.Contains(err.Error(), "cipher: message authentication failed", target)
		}

		// long key should be used as first 32byte key.
		plainTextLongKey, err := DecryptByGCM(cipher1, []byte(longKey))
		a.NoError(err, target)
		a.Equal(tt.text, plainTextLongKey, target)

		plainText2, err := DecryptByGCM(cipher2, []byte(invalidKey))
		a.NoError(err, target)
		a.Equal(tt.text, plainText2, target)
	}
}
