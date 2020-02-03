package balloon

import (
	"crypto/sha512"
	"encoding/hex"
	"hash"

	"github.com/nogoegst/balloon"
)

const (
	// see: https://godoc.org/github.com/nogoegst/balloon
	defaultSpaceCost   = 16
	defaultTimeCost    = 16
	defaultParallelism = 1
)

var (
	defaultHashFn = sha512.New
)

// Balloon is struct to create hash.
type Balloon struct {
	HashFn      func() hash.Hash
	SpaceCost   uint64
	TimeCost    uint64
	Parallelism uint64 // p
}

// Hash creates hased text from password.
func (b Balloon) Hash(password, salt string) string {
	return hex.EncodeToString(balloon.BalloonM(
		b.getHashFn(),
		[]byte(password),
		[]byte(salt),
		b.getSpaceCost(),
		b.getTimeCost(),
		b.getParallelism(),
	))
}

func (b Balloon) getHashFn() func() hash.Hash {
	if b.HashFn == nil {
		return defaultHashFn
	}
	return b.HashFn
}

func (b Balloon) getSpaceCost() uint64 {
	if b.SpaceCost == 0 {
		return defaultSpaceCost
	}
	return b.SpaceCost
}

func (b Balloon) getTimeCost() uint64 {
	if b.TimeCost == 0 {
		return defaultTimeCost
	}
	return b.TimeCost
}

func (b Balloon) getParallelism() uint64 {
	if b.Parallelism == 0 {
		return defaultParallelism
	}
	return b.Parallelism
}
