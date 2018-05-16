package hierogolyph

import (
	"encoding/base64"
	"unicode/utf8"
)

// paddingLeft adds pad string into left side of str.
func paddingLeft(str string, length int, pad string) string {
	return padding(pad, length-utf8.RuneCountInString(str)) + str
}

func padding(pad string, length int) (result string) {
	for i := 0; i < length; i++ {
		result += pad
	}
	return result
}

func encodeBase64(byt []byte) string {
	return base64.StdEncoding.EncodeToString(byt)
}

func encodeBase64String(text string) string {
	return encodeBase64([]byte(text))
}

func decodeBase64(text string) (string, error) {
	s, err := base64.StdEncoding.DecodeString(text)
	return string(s), err
}
