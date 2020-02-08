package awskms

import (
	"strings"

	"github.com/evalphobia/aws-sdk-go-wrapper/kms"
)

const (
	encryptionPrefix = "AWSKMSx"
)

// HSM is struct for AWS KMS.
type HSM struct {
	KMS     *kms.KMS
	KeyName string
}

// NewHSM creates new HSM.
func NewHSM(cli *kms.KMS, keyName string) *HSM {
	return &HSM{
		KMS:     cli,
		KeyName: keyName,
	}
}

// Encrypt encrypts plainText and adds prefix.
func (h *HSM) Encrypt(plainText string) (cipherText string, err error) {
	str, err := h.KMS.EncryptString(h.KeyName, plainText)
	return encryptionPrefix + str, err
}

// Decrypt decrypts prefixed cipherByte.
func (h *HSM) Decrypt(cipherByte []byte) (plainText string, err error) {
	str, err := h.KMS.DecryptString(strings.TrimPrefix(string(cipherByte), encryptionPrefix))
	return str, err
}
