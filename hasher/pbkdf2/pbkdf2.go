package pbkdf2

import (
	"crypto/sha512"
	"encoding/hex"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// see: https://godoc.org/golang.org/x/crypto/pbkdf2
	defaultIterationSize = 4096
	defaultKeyLength     = 32
)

var (
	defaultHashFn = sha512.New
)

// PBKDF2 is struct to create hash.
type PBKDF2 struct {
	HashFn        func() hash.Hash
	IterationSize int
	KeyLength     int
}

// Hash creates hased text from password.
func (p PBKDF2) Hash(password, salt string) string {
	return hex.EncodeToString(pbkdf2.Key(
		[]byte(password),
		[]byte(salt),
		p.getIterationSize(),
		p.getKeyLength(),
		p.getHashFn(),
	))
}

func (p PBKDF2) getHashFn() func() hash.Hash {
	if p.HashFn == nil {
		return defaultHashFn
	}
	return p.HashFn
}

func (p PBKDF2) getIterationSize() int {
	if p.IterationSize == 0 {
		return defaultIterationSize
	}
	return p.IterationSize
}

func (p PBKDF2) getKeyLength() int {
	if p.KeyLength == 0 {
		return defaultKeyLength
	}
	return p.KeyLength
}
