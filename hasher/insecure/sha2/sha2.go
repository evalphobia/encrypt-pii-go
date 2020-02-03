package sha2

import (
	"encoding/hex"

	"crypto/sha256"
	"crypto/sha512"
)

// Sha512 is struct to create hash.
type Sha512 struct{}

// Hash creates hased text from password.
func (Sha512) Hash(password, salt string) string {
	b := sha512.Sum512_256([]byte(password + salt))
	return hex.EncodeToString(b[:])
}

// Sha256 is struct to create hash.
type Sha256 struct{}

// Hash creates hased text from password.
func (Sha256) Hash(password, salt string) string {
	b := sha256.Sum256([]byte(password + salt))
	return hex.EncodeToString(b[:])
}
