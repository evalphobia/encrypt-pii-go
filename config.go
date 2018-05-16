package hierogolyph

import (
	"github.com/evalphobia/hierogolyph/cipher"
	"github.com/evalphobia/hierogolyph/hasher"
	"github.com/evalphobia/hierogolyph/hsm"
)

type Config struct {
	// Cipher is the main algorithm to encrypt/decrypt text.
	// (e,g, AES GCM)
	Cipher cipher.Cipher

	// HSM is Hardware Security Module
	// (e.g. AWS KMS)
	HSM hsm.HSM

	// Hasher is hashing algorithm.
	// (e.g. Argon2, Scrypt)
	Hasher hasher.Hasher

	// HMACKey is the key used for signing message with HMAC.
	HMACKey string
}
