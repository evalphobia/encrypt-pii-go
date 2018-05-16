package hierogolyph

import (
	"fmt"
	"testing"

	"github.com/evalphobia/hierogolyph/cipher/aesgcm"
	"github.com/evalphobia/hierogolyph/hasher/argon2"
	hsmgcm "github.com/evalphobia/hierogolyph/hsm/aesgcm"

	"github.com/stretchr/testify/assert"
)

const (
	testHMACKey   = `nzgz8CX^aB9v:^{iOp[F}>|%h_116]^"m*=v&O4mpA?S_W)\BN]%]_o>hl$1Y^Sb`
	testGCMKey256 = `PD02lR@Wb^P/PFh$E79v5aWu{W,Ap\e;`
)

var testConfig = Config{
	Cipher:  aesgcm.CipherGCM{},
	HSM:     hsmgcm.NewAesGcm([]byte(testGCMKey256)),
	Hasher:  argon2.Argon2{},
	HMACKey: testHMACKey,
}

type testHierogolyphData struct {
	password   string
	secretText string
}

func TestHierogolyph(t *testing.T) {
	a := assert.New(t)

	tests := []testHierogolyphData{
		{"password", "secretText"},
		{"password", "secretText2"},
		{"", "secretText"},
		{"it's my secret", "secretText"},
		{"jsos data password", `{
			"error": "Expected a ',' or '}' at 15 [character 16 line 1]",
			"object_or_array": "object",
			"error_info": "This error came from the org.json reference parser.",
			"validate": false
		 }`},
	}

	for _, tt := range tests {
		testHierogolyph(t, a, tt)
	}
}

func TestHierogolyphBigData(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	a := assert.New(t)

	tests := []struct {
		password string
		dataSize int
	}{
		{"password 1KB", 1024 * 1},
		{"password 10KB", 1024 * 10},
		{"password 100KB", 1024 * 100},
		{"password 1MB", 1024 * 1024},
		{"password 10MB", 1024 * 1024 * 10},
		{"password 100MB", 1024 * 1024 * 100},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)
		data, err := getRandomBytes(tt.dataSize)
		a.NoError(err, target)
		a.Len(data, tt.dataSize, target)

		testHierogolyph(t, a, testHierogolyphData{
			password:   tt.password,
			secretText: string(data),
		})
	}
}

func testHierogolyph(t *testing.T, a *assert.Assertions, tt testHierogolyphData) {
	target := fmt.Sprintf("%+v", tt)

	// create struct
	h, err := CreateHierogolyph(tt.password, testConfig)
	a.NoError(err, target)

	// encryption
	cipherText, err := h.Encrypt(tt.secretText)
	a.NoError(err, target)

	// recreate Hierogolyph
	h = Hierogolyph{
		Config:   testConfig,
		Password: tt.password,
		Salt:     h.Salt,
	}

	// decryption
	plainText, err := h.Decrypt(cipherText)
	a.NoError(err, target)
	a.Equal(tt.secretText, plainText, target)

	// try different HMAC Key
	h.Config.HMACKey = testHMACKey + "12345"
	_, err = h.Decrypt(cipherText)
	if a.Error(err, target) {
		a.Contains(err.Error(), "HMAC finger print error:", target)
	}

	// try different HSM
	h.Config.HSM = hsmgcm.NewAesGcm([]byte("12345678901234567890123456789012"))
	_, err = h.Decrypt(cipherText)
	if a.Error(err, target) {
		a.Contains(err.Error(), "cipher: message authentication failed", target)
	}
}

func TestCreateDigests(t *testing.T) {
	a := assert.New(t)

	tests := []struct {
		password string
		salt     string
		expected string
	}{
		{"", "", "5128a67536615d0bbd8558960b91db999cabb39f04d76a777beb868efba204ab"},
		{"aaa", "", "3b9c3959d45fc8f4741eea27638a8298dde57e415cb67f19cb62f5fea6e11e86"},
		{"", "aaa", "5ef4072c18a4a914d1b7ce9815a8114b68a7de6d2ae28c6b8e8ee5af46107cfd"},
		{"a", "aa", "1d00ecf79ff848eeee3ab8ce8c5933f021bf5b15406da89cbf01ecdda906fb53"},
		{"aa", "a", "c0ea934aa76c5030439ebb02b9ccb5e625ba105efcca26544fed3894746e9368"},
		{"a", "aaa", "d4bae9a824aa9417cb079b39001b208e52926aa12baca57f6526c471db8f6cae"},
		{"aaa", "a", "292f69eccd0d061d5e0b93483d1eefcb55420d34e7d13ecc92ed0cb43921d8c5"},
		{"1234", "5678", "9272cd4ccd4f23f9d069bbd7b2d78f27cfedd7b4c49d5f4927ca10cb62ffe04c"},
	}

	hasher := argon2.Argon2{}
	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)
		z1, z2 := createDigests(tt.password, tt.salt, hasher)
		a.Len(z1, 32, target)
		a.Len(z2, 32, target)
		a.Equal(tt.expected, z1+z2, target)
	}
}

func TestCreateEncryptionKey(t *testing.T) {
	a := assert.New(t)

	tests := []struct {
		a string
		b string
	}{
		{"", ""},
		{"aaa", ""},
		{"", "aaa"},
		{"a", "aa"},
		{"aa", "a"},
		{"a", "aaa"},
		{"aaa", "a"},
		{"1234", "5678"},
	}

	gcm := hsmgcm.NewAesGcm([]byte(testGCMKey256))
	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)
		result1, err := createEncryptionKey(tt.a, tt.b, gcm)
		a.NoError(err, target)
		a.True(len(result1) > 0, target)

		// confirm every outputs are different
		result2, err := createEncryptionKey(tt.a, tt.b, gcm)
		a.NoError(err, target)
		a.True(len(result2) > 0, target)
		a.NotEqual(result1, result2, target)
	}
}

func TestCreateCEK(t *testing.T) {
	a := assert.New(t)

	tests := []struct {
		a        string
		b        string
		expected string
	}{
		{"", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"aaa", "", "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"},
		{"", "aaa", "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"},
		{"a", "aa", "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"},
		{"aa", "a", "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"},
		{"a", "aaa", "61be55a8e2f6b4e172338bddf184d6dbee29c98853e0a0485ecee7f27b9af0b4"},
		{"aaa", "a", "61be55a8e2f6b4e172338bddf184d6dbee29c98853e0a0485ecee7f27b9af0b4"},
		{"1234", "5678", "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f"},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)
		cek := createCEK(tt.a, tt.b)
		a.Equal(tt.expected, cek, target)
	}
}

func TestXOR(t *testing.T) {
	a := assert.New(t)

	tests := []struct {
		a        string
		b        string
		expected []byte
	}{
		{"", "", []byte("")},
		{"aaa", "", []byte("QQQ")},
		{"", "aaa", []byte("")},
		{"a", "aa", []byte("\x00")},
		{"aa", "a", []byte("Q\x00")},
		{"a", "aaa", []byte("\x00")},
		{"aaa", "a", []byte("QQ\x00")},
		{"1234", "1234", []byte("\x00\x00\x00\x00")},
		{"5678", "5678", []byte("\x00\x00\x00\x00")},
		{"1234", "5678", []byte("\x04\x04\x04\f")},
		{"5678", "1234", []byte("\x04\x04\x04\f")},
		{"1234", "56789", []byte("\x04\x04\x04\f")},
		{"12345", "5678", []byte("\x01\a\x05\x03\r")},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)
		result := xor(tt.a, tt.b)
		a.Equal(string(tt.expected), string(result), target)
	}
}
