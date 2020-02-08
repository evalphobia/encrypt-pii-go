package crypto

import (
	"strings"
	"testing"

	"github.com/evalphobia/hierogolyph/crypto/aesgcm"
	"github.com/evalphobia/hierogolyph/crypto/chacha20poly1305"
)

var (
	key = []byte("12345678901234567890123456789012")

	bechmarkText445   = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
	bechmarkText2k    = strings.Repeat("abcdefghijklmnop", 128) // 16*128
	bechmarkTextMB10  = "あいうえおかきくけこ"                            // 10 * 3byte (multi-byte char)
	bechmarkTextMB10k = strings.Repeat(bechmarkTextMB10, 1000)  // 30byte * 10k = 30KB
)

func BenchmarkEncryptByAesGcm(b *testing.B) {
	b.Run("445byte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := aesgcm.Encrypt(bechmarkText445, key)
			if err != nil {
				panic(err)
			}
		}
	})
	b.Run("2Kbyte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := aesgcm.Encrypt(bechmarkText2k, key)
			if err != nil {
				panic(err)
			}
		}
	})
	b.Run("30Kbyte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := aesgcm.Encrypt(bechmarkTextMB10k, key)
			if err != nil {
				panic(err)
			}
		}
	})
}

func BenchmarkDecryptByAesGcm(b *testing.B) {
	cipherText445, err := aesgcm.Encrypt(bechmarkText445, key)
	if err != nil {
		panic(err)
	}
	cipherText2k, err := aesgcm.Encrypt(bechmarkText2k, key)
	if err != nil {
		panic(err)
	}
	cipherText30k, err := aesgcm.Encrypt(bechmarkTextMB10k, key)
	if err != nil {
		panic(err)
	}

	b.Run("445byte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := aesgcm.Decrypt(cipherText445, key)
			if err != nil {
				panic(err)
			}
		}
	})
	b.Run("2Kbyte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := aesgcm.Decrypt(cipherText2k, key)
			if err != nil {
				panic(err)
			}
		}
	})
	b.Run("30Kbyte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := aesgcm.Decrypt(cipherText30k, key)
			if err != nil {
				panic(err)
			}
		}
	})
}

func BenchmarkEncryptByChaCha(b *testing.B) {
	b.Run("445byte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := chacha20poly1305.Encrypt(bechmarkText445, key)
			if err != nil {
				panic(err)
			}
		}
	})
	b.Run("2Kbyte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := chacha20poly1305.Encrypt(bechmarkText2k, key)
			if err != nil {
				panic(err)
			}
		}
	})
	b.Run("30Kbyte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := chacha20poly1305.Encrypt(bechmarkTextMB10k, key)
			if err != nil {
				panic(err)
			}
		}
	})
}

func BenchmarkDecryptByChaCha(b *testing.B) {
	cipherText445, err := chacha20poly1305.Encrypt(bechmarkText445, key)
	if err != nil {
		panic(err)
	}
	cipherText2k, err := chacha20poly1305.Encrypt(bechmarkText2k, key)
	if err != nil {
		panic(err)
	}
	cipherText30k, err := chacha20poly1305.Encrypt(bechmarkTextMB10k, key)
	if err != nil {
		panic(err)
	}

	b.Run("445byte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := chacha20poly1305.Decrypt(cipherText445, key)
			if err != nil {
				panic(err)
			}
		}
	})
	b.Run("2Kbyte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := chacha20poly1305.Decrypt(cipherText2k, key)
			if err != nil {
				panic(err)
			}
		}
	})
	b.Run("30Kbyte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := chacha20poly1305.Decrypt(cipherText30k, key)
			if err != nil {
				panic(err)
			}
		}
	})
}
