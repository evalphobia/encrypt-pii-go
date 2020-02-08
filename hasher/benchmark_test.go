package hasher

import (
	"strings"
	"testing"

	"github.com/evalphobia/hierogolyph/hasher/argon2"
	"github.com/evalphobia/hierogolyph/hasher/balloon"
	"github.com/evalphobia/hierogolyph/hasher/insecure/blake2"
	"github.com/evalphobia/hierogolyph/hasher/insecure/sha2"
	"github.com/evalphobia/hierogolyph/hasher/insecure/sha3"
	"github.com/evalphobia/hierogolyph/hasher/pbkdf2"
	"github.com/evalphobia/hierogolyph/hasher/scrypt"
)

var (
	bechmarkText10  = "abcdefghij"
	bechmarkText16  = "abcdefghijklmnop"
	bechmarkText32  = strings.Repeat(bechmarkText16, 2) // 16*2
	bechmarkText64  = strings.Repeat(bechmarkText16, 4) // 16*4
	bechmarkText128 = strings.Repeat(bechmarkText16, 8) // 16*8

	bechmarkSalt32 = strings.Repeat("1234", 8) // 4*8
)

func BenchmarkHashSecure(b *testing.B) {
	b.Run("Argon2id", func(b *testing.B) {
		runHash(b, argon2.Argon2{}.Hash)
	})
	b.Run("Balloon", func(b *testing.B) {
		runHash(b, balloon.Balloon{}.Hash)
	})
	b.Run("PBKDF2", func(b *testing.B) {
		runHash(b, pbkdf2.PBKDF2{}.Hash)
	})
	b.Run("SCrypt", func(b *testing.B) {
		runHash(b, scrypt.SCrypt{}.Hash)
	})
}

func BenchmarkHashInsecure(b *testing.B) {
	b.Run("blake2", func(b *testing.B) {
		runHash(b, blake2.Blake2b{}.Hash)
	})
	b.Run("sha2-512", func(b *testing.B) {
		runHash(b, sha2.Sha512{}.Hash)
	})
	b.Run("sha3-256", func(b *testing.B) {
		runHash(b, sha3.Sha256{}.Hash)
	})
}

func runHash(b *testing.B, hashFunc func(string, string) string) {
	b.Run("10byte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = hashFunc(bechmarkText10, bechmarkSalt32)
		}
	})
	b.Run("16byte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = hashFunc(bechmarkText16, bechmarkSalt32)
		}
	})
	b.Run("32byte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = hashFunc(bechmarkText32, bechmarkSalt32)
		}
	})
	b.Run("64byte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = hashFunc(bechmarkText64, bechmarkSalt32)
		}
	})
	b.Run("128byte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = hashFunc(bechmarkText128, bechmarkSalt32)
		}
	})
}
