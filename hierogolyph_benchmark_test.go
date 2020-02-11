package hierogolyph

import (
	"strings"
	"testing"

	"github.com/evalphobia/hierogolyph/cipher/aesgcm"
	"github.com/evalphobia/hierogolyph/cipher/chacha20poly1305"
	"github.com/evalphobia/hierogolyph/hasher/argon2"
	"github.com/evalphobia/hierogolyph/hasher/balloon"
	hsmgcm "github.com/evalphobia/hierogolyph/hsm/aesgcm"
	hsmchacha "github.com/evalphobia/hierogolyph/hsm/chacha20poly1305"
)

var (
	bechmarkText445   = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
	bechmarkText2k    = strings.Repeat("abcdefghijklmnop", 128) // 16*128
	bechmarkTextMB10  = "あいうえおかきくけこ"                            // 10 * 3byte (multi-byte char)
	bechmarkTextMB10k = strings.Repeat(bechmarkTextMB10, 1000)  // 30byte * 10k = 30KB
)

func Benchmark_Encrypt(b *testing.B) {
	b.Run("Cipher=AESGCM::HSM=AESGCM::Hasher::Argon2id", func(b *testing.B) {
		conf := Config{
			Cipher:  aesgcm.Cipher{},
			HSM:     hsmgcm.NewMockHSM([]byte(testGCMKey256)),
			Hasher:  argon2.Argon2{},
			HMACKey: testHMACKey,
		}
		runEncrypt(b, conf)
	})

	b.Run("Cipher=ChaCha20Poly1302::HSM=ChaCha20Poly1302::Hasher::Argon2id", func(b *testing.B) {
		conf := Config{
			Cipher:  chacha20poly1305.Cipher{},
			HSM:     hsmchacha.NewMockHSM([]byte(testGCMKey256)),
			Hasher:  argon2.Argon2{},
			HMACKey: testHMACKey,
		}
		runEncrypt(b, conf)
	})

	b.Run("Cipher=AESGCM::HSM=AESGCM::Hasher::Balloon", func(b *testing.B) {
		conf := Config{
			Cipher:  aesgcm.Cipher{},
			HSM:     hsmgcm.NewMockHSM([]byte(testGCMKey256)),
			Hasher:  balloon.Balloon{},
			HMACKey: testHMACKey,
		}
		runEncrypt(b, conf)
	})
}

func runEncrypt(b *testing.B, conf Config) {
	h, err := CreateHierogolyph(testHierogolyph1.Password, conf)
	if err != nil {
		b.Error(err)
		return
	}

	b.Run("30byte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = h.Encrypt(bechmarkTextMB10)
			if err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.Run("445byte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = h.Encrypt(bechmarkText445)
			if err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.Run("2Kbyte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = h.Encrypt(bechmarkText2k)
			if err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.Run("30Kbyte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = h.Encrypt(bechmarkTextMB10k)
			if err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func Benchmark_Decrypt(b *testing.B) {
	b.Run("Cipher=AESGCM::HSM=AESGCM::Hasher::Argon2id", func(b *testing.B) {
		conf := Config{
			Cipher:  aesgcm.Cipher{},
			HSM:     hsmgcm.NewMockHSM([]byte(testGCMKey256)),
			Hasher:  argon2.Argon2{},
			HMACKey: testHMACKey,
		}
		runDecrypt(b, conf)
	})

	b.Run("Cipher=ChaCha20Poly1302::HSM=ChaCha20Poly1302::Hasher::Argon2id", func(b *testing.B) {
		conf := Config{
			Cipher:  chacha20poly1305.Cipher{},
			HSM:     hsmchacha.NewMockHSM([]byte(testGCMKey256)),
			Hasher:  argon2.Argon2{},
			HMACKey: testHMACKey,
		}
		runDecrypt(b, conf)
	})

	b.Run("Cipher=AESGCM::HSM=AESGCM::Hasher::Balloon", func(b *testing.B) {
		conf := Config{
			Cipher:  aesgcm.Cipher{},
			HSM:     hsmgcm.NewMockHSM([]byte(testGCMKey256)),
			Hasher:  balloon.Balloon{},
			HMACKey: testHMACKey,
		}
		runDecrypt(b, conf)
	})
}

func runDecrypt(b *testing.B, conf Config) {
	h, err := CreateHierogolyph(testHierogolyph1.Password, conf)
	if err != nil {
		b.Error(err)
		return
	}

	cipher30, err := h.Encrypt(bechmarkTextMB10)
	if err != nil {
		b.Error(err)
		return
	}
	b.Run("30byte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = h.Decrypt(cipher30)
			if err != nil {
				b.Error(err)
				return
			}
		}
	})

	cipher445, err := h.Encrypt(bechmarkText445)
	if err != nil {
		b.Error(err)
		return
	}
	b.Run("445byte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = h.Decrypt(cipher445)
			if err != nil {
				b.Error(err)
				return
			}
		}
	})

	cipher2k, err := h.Encrypt(bechmarkText2k)
	if err != nil {
		b.Error(err)
		return
	}
	b.Run("2Kbyte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = h.Encrypt(cipher2k)
			if err != nil {
				b.Error(err)
				return
			}
		}
	})

	cipher30k, err := h.Encrypt(bechmarkTextMB10k)
	if err != nil {
		b.Error(err)
		return
	}
	b.Run("30Kbyte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = h.Encrypt(cipher30k)
			if err != nil {
				b.Error(err)
				return
			}
		}
	})
}
