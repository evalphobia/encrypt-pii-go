package hierogolyph

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// HashSHA256 returns the SHA256 checksum of the data.
func HashSHA256(data string) string {
	s := sha256.Sum256([]byte(data))
	return hex.EncodeToString(s[:])
}

// HashHMAC returns a HMAC signed message using the given key.
func HashHMAC(plainText, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(plainText))
	return hex.EncodeToString(mac.Sum(nil))
}
