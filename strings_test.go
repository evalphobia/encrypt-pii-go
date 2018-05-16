package hierogolyph

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestPaddingLeft(t *testing.T) {
	a := assert.New(t)

	tests := []struct {
		padSize int
		text    string
	}{
		{0, "aaa"},
		{1, "aaa"},
		{10, "aaa"},
		{100, "aaa"},
		{1000, "aaa"},
		{0, "いろは"},
		{1, "いろは"},
		{10, "いろは"},
	}

	for _, tt := range tests {
		pads := []string{"0", "~", "a", "", "ん"}
		for _, pad := range pads {
			target := fmt.Sprintf("%+v, pad=%s", tt, pad)
			result := paddingLeft(tt.text, tt.padSize, pad)

			textSize := utf8.RuneCountInString(tt.text)
			expectedSize := textSize
			if expectedSize < tt.padSize {
				expectedSize = tt.padSize
			}
			switch {
			case tt.padSize == 0,
				pad == "",
				tt.padSize < textSize:
				a.Equal(tt.text, result, target)
			default:
				a.NotEqual(result, tt.text, target)
				a.Equal(expectedSize, utf8.RuneCountInString(result), target, tt.text, result)
				a.True(strings.Count(result, pad) > 0, target, tt.text, result)
				a.Equal(strings.TrimLeft(result, pad), strings.TrimLeft(tt.text, pad), target)
			}
		}
	}
}

func TestPadding(t *testing.T) {
	a := assert.New(t)

	tests := []struct {
		padSize int
		pad     string
	}{
		{0, "a"},
		{1, "a"},
		{10, "a"},
		{100, "a"},
		{1000, "a"},
		{0, "ん"},
		{1, "ん"},
		{10, "ん"},
		{0, ""},
		{1, ""},
		{10, ""},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)
		result := padding(tt.pad, tt.padSize)

		switch {
		case tt.padSize == 0,
			tt.pad == "":
			a.Equal("", result, target)
		default:
			resultSize := utf8.RuneCountInString(result)
			a.Equal(tt.padSize, resultSize, result)
			a.Equal(tt.padSize, strings.Count(result, tt.pad), result)
			a.Equal(strings.TrimLeft(result, tt.pad), "", target)
		}
	}
}

type testBase64 struct {
	plainText   string
	encodedText string
}

var testBase64Data = []testBase64{
	{"", ""},
	{"a", "YQ=="},
	{"abc", "YWJj"},
	{"1234567890", "MTIzNDU2Nzg5MA=="},
}

func TestEncodeBase64(t *testing.T) {
	a := assert.New(t)

	tests := testBase64Data
	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)
		result := encodeBase64([]byte(tt.plainText))
		a.Equal(tt.encodedText, result, target)
	}
}

func TestEncodeBase64String(t *testing.T) {
	a := assert.New(t)

	tests := testBase64Data
	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)
		result := encodeBase64String(tt.plainText)
		a.Equal(tt.encodedText, result, target)
	}
}

func TestDecodeBase64(t *testing.T) {
	a := assert.New(t)

	tests := testBase64Data
	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)
		result, err := decodeBase64(tt.encodedText)
		a.NoError(err, target)
		a.Equal(tt.plainText, result, target)
	}
}
