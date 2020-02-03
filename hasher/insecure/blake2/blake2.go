package blake2

import (
	"encoding/hex"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
)

// Blake2b is struct to create hash.
type Blake2b struct{}

// Hash creates hased text from password.
func (Blake2b) Hash(password, salt string) string {
	b := blake2b.Sum256([]byte(password + salt))
	return hex.EncodeToString(b[:])
}

// Blake2s is struct to create hash.
type Blake2s struct{}

// Hash creates hased text from password.
func (Blake2s) Hash(password, salt string) string {
	b := blake2s.Sum256([]byte(password + salt))
	return hex.EncodeToString(b[:])
}
