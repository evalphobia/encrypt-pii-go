package awskms

import (
	"fmt"
	"strings"
	"testing"

	"github.com/evalphobia/aws-sdk-go-wrapper/config"
	"github.com/evalphobia/aws-sdk-go-wrapper/kms"
	"github.com/stretchr/testify/assert"
)

func TestHSM(t *testing.T) {
	t.Skip()

	a := assert.New(t)

	tests := []struct {
		text string
	}{
		{"a"},
		{"aaa"},
		{"あいうえお"},
	}

	cli, err := kms.New(config.Config{})
	if err != nil {
		panic(err)
	}

	hsmValid := HSM{KMS: cli, KeyName: "alias/foobar"}
	hsmInvalid := HSM{KMS: cli, KeyName: "alias/invalid-keyname"}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)

		// encryption
		cipher1, err := hsmValid.Encrypt(tt.text)
		a.NoError(err, target)
		a.True(strings.HasPrefix(cipher1, encryptionPrefix))

		cipher2, err := hsmInvalid.Encrypt(tt.text)
		if a.Error(err, target) {
			a.Contains(err.Error(), "NotFoundException: Alias arn:aws:kms", target)
		}

		// decryption
		plainText1, err := hsmValid.Decrypt([]byte(cipher1))
		a.NoError(err, target)
		a.Equal(tt.text, plainText1, target)

		// decryption does not use the key name.
		_, err = hsmInvalid.Decrypt([]byte(cipher1))
		a.NoError(err, target)
		a.Equal(tt.text, plainText1, target)

		_, err = hsmInvalid.Decrypt([]byte(cipher2))
		if a.Error(err, target) {
			a.Contains(err.Error(), "InvalidParameter: 1 validation error(s) found.", target)
		}
	}
}

func TestNewHSM(t *testing.T) {
	a := assert.New(t)

	tests := []struct {
		keyName string
	}{
		{"a"},
		{"aaa"},
		{"あいうえお"},
		{""},
		{"12345678901234567890123456789012"},
		{"alias/12345678901234567890123456789012"},
	}

	dummyKMS := &kms.KMS{}
	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)

		hsm := NewHSM(dummyKMS, tt.keyName)
		if a.NotEmpty(hsm, target) {
			a.Equal(tt.keyName, hsm.KeyName, target)
			a.Equal(dummyKMS, hsm.KMS, target)
		}
	}
}
