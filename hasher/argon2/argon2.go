package argon2

import (
	"encoding/hex"

	"golang.org/x/crypto/argon2"
)

const (
	// see: https://godoc.org/golang.org/x/crypto/argon2
	defaultArgon2Time      = 1
	defaultArgon2Memory    = 64 * 1024
	defaultArgon2Threads   = 4
	defaultArgon2KeyLength = 32
)

// Argon2 is struct to create hash using Argon2id.
type Argon2 struct {
	Time      uint32
	Memory    uint32
	Threads   uint8
	KeyLength uint32
}

// Hash creates hased text from password and salt using Argon2id.
func (a Argon2) Hash(password, salt string) string {
	return hex.EncodeToString(argon2.IDKey(
		[]byte(password),
		[]byte(salt),
		a.getTime(),
		a.getMemory(),
		a.getThreads(),
		a.getKeyLength(),
	))
}

func (a Argon2) getTime() uint32 {
	if a.Time == 0 {
		return defaultArgon2Time
	}
	return a.Time
}

func (a Argon2) getMemory() uint32 {
	if a.Memory == 0 {
		return defaultArgon2Memory
	}
	return a.Memory
}

func (a Argon2) getThreads() uint8 {
	if a.Threads == 0 {
		return defaultArgon2Threads
	}
	return a.Threads
}

func (a Argon2) getKeyLength() uint32 {
	if a.KeyLength == 0 {
		return defaultArgon2KeyLength
	}
	return a.KeyLength
}
