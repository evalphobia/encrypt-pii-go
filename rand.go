package hierogolyph

import "crypto/rand"

const (
	letters       = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
	letterSize    = len(letters)
	letterIdxMask = 0x7F // 127
)

// getRandomString gets random strings which has given length.
// The characters are used from `letters`.
func getRandomString(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	for i := 0; i < length; {
		idx := int(buf[i] & letterIdxMask)
		if idx < letterSize {
			buf[i] = letters[idx]
			i++
		} else {
			if _, err := rand.Read(buf[i : i+1]); err != nil {
				return "", err
			}
		}
	}
	return string(buf), nil
}

// getRandomBytes gets random bytes which has given length.
func getRandomBytes(length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := rand.Read(buf)
	return buf, err
}
