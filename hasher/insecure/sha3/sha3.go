package sha3

import (
	"encoding/hex"

	"golang.org/x/crypto/sha3"
)

// Sha256 is struct to create hash.
type Sha256 struct{}

// Hash creates hased text from password.
func (Sha256) Hash(password, salt string) string {
	b := sha3.Sum256([]byte(password + salt))
	return hex.EncodeToString(b[:])
}
