package scrypt

import (
	"encoding/hex"

	"golang.org/x/crypto/scrypt"
)

const (
	// see: https://godoc.org/golang.org/x/crypto/scrypt
	defaultCost        = 32768
	defaultBlockSize   = 8
	defaultParallelism = 1
	defaultKeyLength   = 32
)

// SCrypt is struct to create hash.
type SCrypt struct {
	Cost        int // N
	BlockSize   int // r
	Parallelism int // p
	KeyLength   int
}

// Hash creates hased text from password.
func (s SCrypt) Hash(password, salt string) string {
	hash, err := scrypt.Key(
		[]byte(password),
		[]byte(salt),
		s.getCost(),
		s.getBlockSize(),
		s.getParallelism(),
		s.getKeyLength(),
	)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(hash)
}

func (s SCrypt) getCost() int {
	if s.Cost == 0 {
		return defaultCost
	}
	return s.Cost
}

func (s SCrypt) getBlockSize() int {
	if s.BlockSize == 0 {
		return defaultBlockSize
	}
	return s.BlockSize
}

func (s SCrypt) getParallelism() int {
	if s.Parallelism == 0 {
		return defaultParallelism
	}
	return s.Parallelism
}

func (s SCrypt) getKeyLength() int {
	if s.KeyLength == 0 {
		return defaultKeyLength
	}
	return s.KeyLength
}
