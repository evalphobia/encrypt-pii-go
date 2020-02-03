package chacha20poly1305

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHSM(t *testing.T) {
	a := assert.New(t)
	validKey := "12345678901234567890123456789012" // 32byte
	invalidKey := "X2345678901234567890123456789012"
	shortKey := "too short"

	tests := []struct {
		text string
	}{
		{"a"},
		{"aaa"},
		{"あいうえお"},
		{""},
	}

	hsmValid := MockHSM{Key: []byte(validKey)}
	hsmInvalid := MockHSM{Key: []byte(invalidKey)}
	hsmShortKey := MockHSM{Key: []byte(shortKey)}
	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)

		_, err := hsmShortKey.Encrypt(tt.text)
		if a.Error(err, "using short key") {
			a.Contains(err.Error(), "chacha20poly1305: bad key length", target, "using short key")
		}

		// encryption
		cipher1, err := hsmValid.Encrypt(tt.text)
		a.NoError(err, target)
		a.True(strings.HasPrefix(cipher1, encryptionPrefix))

		cipher2, err := hsmInvalid.Encrypt(tt.text)
		a.NoError(err, target)
		a.NotEqual(cipher1, cipher2, target, "using invalid key")
		a.True(strings.HasPrefix(cipher2, encryptionPrefix))

		// decryption
		plainText1, err := hsmValid.Decrypt([]byte(cipher1))
		a.NoError(err, target)
		a.Equal(tt.text, plainText1, target)

		_, err = hsmInvalid.Decrypt([]byte(cipher1))
		if a.Error(err, target) {
			a.Contains(err.Error(), "chacha20poly1305: message authentication failed", target)
		}

		plainText2, err := hsmInvalid.Decrypt([]byte(cipher2))
		a.NoError(err, target)
		a.Equal(tt.text, plainText2, target)
	}
}

func TestNewMockHSM(t *testing.T) {
	a := assert.New(t)

	tests := []struct {
		key         string
		expectedKey string
	}{
		{"a", "a"},
		{"aaa", "aaa"},
		{"あいうえお", "あいうえお"},
		{"", ""},
		{"12345678901234567890123456789012", "12345678901234567890123456789012"},
		// more than 32byte keys
		{"123456789012345678901234567890123", "12345678901234567890123456789012"},
		{"12345678901234567890123456789012XYZ", "12345678901234567890123456789012"},
		{"00000000000000000000000000000000XYZ", "00000000000000000000000000000000"},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)

		hsm := NewMockHSM([]byte(tt.key))
		if a.NotEmpty(hsm, target) {
			a.Equal(tt.expectedKey, string(hsm.Key), target)
		}
	}
}
