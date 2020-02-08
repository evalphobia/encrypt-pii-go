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

const (
	// error messages
	errInvalidCipher = "cipher: message authentication failed"
	errDecodeBase64  = "illegal base64 data at input byte 0"
	errEmptyKey      = "cipherText is too short: textsize=[0], noncesize=[12]"
)

var (
	// test data for Unlock/Encrypt/Decrypt
	testHierogolyph1 = Hierogolyph{
		Password:      "password",
		Salt:          "salt",
		EncryptionKey: "d3N9SCtk5BNUuntNuSAKLi8X8MCMlGWJGMFyMi7y5WhfZh2bjEskaIfFOD3T+pE3Mf157vhJ5iN2h30jwUAPtg==",
	}
	testHierogolyph2 = Hierogolyph{
		Password:      "password",
		Salt:          "salt2",
		EncryptionKey: "d3N9SEzjdDohqDNG0rPd1jFIwA6KDHd7M/nYoNKF3/3B9H3QnhRrrK86LDCulUfYJ+VZEvvfmeg+8v6MPtdAlA==",
	}
	testHierogolyph3 = Hierogolyph{
		Password:      "password2",
		Salt:          "salt",
		EncryptionKey: "d3N9SC48GxcrG8Q/6lm/UT3Vhzp63oAsDNqzdz0JuGs44fBmQP87mOEOM1hzd/LaaggK9TV3ChE0XmcnGP0RtQ==",
	}
)

var testConfig = Config{
	Cipher:  aesgcm.Cipher{},
	HSM:     hsmgcm.NewMockHSM([]byte(testGCMKey256)),
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
	originalSalt := h.Salt
	var originalCipherText string

	// encryption and decryption
	{
		// encryption
		cipherText, err := h.Encrypt(tt.secretText)
		originalCipherText = cipherText
		a.NoError(err, target)

		// decryption by new instance
		h2 := Hierogolyph{
			Config:   testConfig,
			Password: tt.password,
			Salt:     originalSalt,
		}
		plainText, err := h2.Decrypt(cipherText)
		a.NoError(err, target)
		a.Equal(tt.secretText, plainText, target)
	}

	// re-encryption by new instance
	{
		// decryption by new instance
		h3 := Hierogolyph{
			Config:   testConfig,
			Password: tt.password,
			Salt:     originalSalt,
		}
		plainText, err := h3.Decrypt(originalCipherText)
		a.NoError(err, target)
		a.Equal(tt.secretText, plainText, target)

		// re-encryption
		err = h.SetEncryptionKey()
		a.NoError(err, target)
		_, err = h.Encrypt(tt.secretText)
		a.NoError(err, target)
	}

	// try different HMAC Key
	h.Config.HMACKey = testHMACKey + "12345"
	_, err = h.Decrypt(originalCipherText)
	if a.Error(err, target) {
		a.Contains(err.Error(), "HMAC finger print error:", target)
	}

	// try different HSM
	h.Config.HSM = hsmgcm.NewMockHSM([]byte("12345678901234567890123456789012"))
	_, err = h.Decrypt(originalCipherText)
	if a.Error(err, target) {
		a.Contains(err.Error(), "cipher: message authentication failed", target)
	}
}

func TestHierogolyph_EncryptionKey(t *testing.T) {
	a := assert.New(t)
	tests := []struct {
		password string
		salt     string
	}{
		{"password", "12345678901234567890"},
		{"password", ""},
		{"password", "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},
		{"", "12345678901234567890"},
		{"", ""},
		{"password", "salt"},
	}

	t.Run("SetEncryptionKey", func(t *testing.T) {
		for _, tt := range tests {
			target := fmt.Sprintf("%+v", tt)

			h := Hierogolyph{
				Config:   testConfig,
				Password: tt.password,
				Salt:     tt.salt,
			}
			a.Empty(h.EncryptionKey, target)

			err := h.SetEncryptionKey()
			a.NoError(err, target)
			a.NotEmpty(h.EncryptionKey, target)

			decoded, err := decodeBase64(h.EncryptionKey)
			a.NotEmpty(decoded, target)
			a.NoError(err, target)
		}
	})

	t.Run("createEncryptionKey", func(t *testing.T) {
		for _, tt := range tests {
			target := fmt.Sprintf("%+v", tt)

			h := Hierogolyph{
				Config:   testConfig,
				Password: tt.password,
				Salt:     tt.salt,
			}
			a.Empty(h.EncryptionKey, target)

			ek, err := h.createEncryptionKey()
			a.NoError(err, target)
			a.NotEmpty(ek, target)
			a.Empty(h.EncryptionKey, target)

			decoded, err := decodeBase64(ek)
			a.NotEmpty(decoded, target)
			a.NoError(err, target)
			t.Logf("Password:[%s] Salt:[%s] EK:[%s]\n", tt.password, tt.salt, ek)
		}
	})
}

func TestHierogolyph_Unlock(t *testing.T) {
	a := assert.New(t)

	const (
		expectedCEK1 = "0092d011b191db7be716bf09ef7a26edde6b56525875842ead14b1dae561ff20"
		expectedCEK2 = "60090ff6161d66a61a84b1a0b6a8074dc61e08ebb27cbce164b69a2f627af330"
		expectedCEK3 = "08a2b950e712fdeeae72634a5b10fa1bd1293e37da1da1ae651180495385eb9a"
		emptyCEK     = ""
	)
	h1 := testHierogolyph1
	h2 := testHierogolyph2
	h3 := testHierogolyph3

	tests := []struct {
		errMessage  string
		password    string
		salt        string
		ek          string
		expectedCEK string
	}{
		// success
		{"", h1.Password, h1.Salt, h1.EncryptionKey, expectedCEK1},
		{"", h2.Password, h2.Salt, h2.EncryptionKey, expectedCEK2},
		{"", h3.Password, h3.Salt, h3.EncryptionKey, expectedCEK3},

		// error
		{errInvalidCipher, "password", "bad salt", h1.EncryptionKey, emptyCEK},
		{errInvalidCipher, "bad password", "salt", h1.EncryptionKey, emptyCEK},
		{errInvalidCipher, "password", "salt", h2.EncryptionKey, emptyCEK},
		{errInvalidCipher, "password", "salt2", h1.EncryptionKey, emptyCEK},
		{errInvalidCipher, "password2", "salt", h1.EncryptionKey, emptyCEK},
		{errDecodeBase64, "password", "salt", "ek", emptyCEK},
		{errEmptyKey, "password", "salt", "", emptyCEK},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)

		h := Hierogolyph{
			Config:        testConfig,
			Password:      tt.password,
			Salt:          tt.salt,
			EncryptionKey: tt.ek,
		}

		cek, err := h.Unlock()
		if tt.errMessage != "" {
			a.EqualError(err, tt.errMessage, target)
			continue
		}

		a.NoError(err, target)
		a.Equal(tt.expectedCEK, cek, target)
	}
}

func TestHierogolyph_Encrypt(t *testing.T) {
	a := assert.New(t)
	h1 := testHierogolyph1
	h2 := testHierogolyph2

	tests := []struct {
		errMessage string
		password   string
		salt       string
		ek         string
	}{
		// success
		{"", h1.Password, h1.Salt, h1.EncryptionKey},
		{"", h2.Password, h2.Salt, h2.EncryptionKey},

		// error
		{errInvalidCipher, h1.Password, h1.Salt, h2.EncryptionKey},
		{errDecodeBase64, h1.Password, h1.Salt, "ek"},
		{errEmptyKey, h1.Password, h1.Salt, ""},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)

		h := Hierogolyph{
			Config:        testConfig,
			Password:      tt.password,
			Salt:          tt.salt,
			EncryptionKey: tt.ek,
		}
		platinText := "plain text"

		cipherText, err := h.Encrypt(platinText)
		if tt.errMessage != "" {
			a.EqualError(err, tt.errMessage, target)
			continue
		}

		a.NoError(err, target)
		a.NotEmpty(cipherText, target)

		// try empty hsm key
		h.Config.HSM = hsmgcm.NewMockHSM(nil)
		_, err = h.Encrypt(platinText)
		a.EqualError(err, "crypto/aes: invalid key size 0", target)
	}
}

func TestHierogolyph_Decrypt(t *testing.T) {
	a := assert.New(t)
	h1 := testHierogolyph1
	h2 := testHierogolyph2

	cipherText1 := "ZDNOOVNDdGs1Qk5VdW50TnVTQUtMaThYOE1DTWxHV0pHTUZ5TWk3eTVXaGZaaDJiakVza2FJZkZPRDNUK3BFM01mMTU3dmhKNWlOMmgzMGp3VUFQdGc9PQ==.AsBEVSwjdTlK38BJR72naWQe5Y0IgP4QmYXbreRcd9HmZMCxt6+yCQvMSLc1rgkLD2NYUMT68aUO02vcq4oZpBbERjn0liKe8Wsmmjqnvu+XGiPwFLnQHzw86KSlKM+m5V4u4KYruiCfD7vBy5Ls0koPxRHAoUsiZ4/f79IQJjQpZLzAIA=="

	tests := []struct {
		errMessage string
		cipherText string
		password   string
		salt       string
		ek         string
	}{
		// success
		{"", cipherText1, h1.Password, h1.Salt, h1.EncryptionKey},

		// error
		{errInvalidCipher, cipherText1, h2.Password, h2.Salt, h2.EncryptionKey},
		{errDecodeBase64, "a.b", h1.Password, h1.Salt, h1.EncryptionKey},
		{errEmptyKey, ".", h1.Password, h1.Salt, h1.EncryptionKey},
		{"cipherText=[] must have one dot `.`", "", h1.Password, h1.Salt, h1.EncryptionKey},
		{"cipherText=[abcde] must have one dot `.`", "abcde", h1.Password, h1.Salt, h1.EncryptionKey},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)

		h := Hierogolyph{
			Config:        testConfig,
			Password:      tt.password,
			Salt:          tt.salt,
			EncryptionKey: tt.ek,
		}

		plainText, err := h.Decrypt(tt.cipherText)
		if tt.errMessage != "" {
			a.EqualError(err, tt.errMessage, target)
			continue
		}

		a.NoError(err, target)
		a.Equal("plain text", plainText, target)

		// try empty hsm key
		h.Config.HSM = hsmgcm.NewMockHSM(nil)
		_, err = h.Decrypt(tt.cipherText)
		a.EqualError(err, "crypto/aes: invalid key size 0", target)
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

func Test_createEncryptionKey(t *testing.T) {
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

	gcm := hsmgcm.NewMockHSM([]byte(testGCMKey256))
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
