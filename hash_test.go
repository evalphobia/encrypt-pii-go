package hierogolyph

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashSHA256(t *testing.T) {
	a := assert.New(t)

	tests := []struct {
		text     string
		expected string
	}{
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
		{"aaa", "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"},
		{"あいうえお", "fdb481ea956fdb654afcc327cff9b626966b2abdabc3f3e6dbcb1667a888ed9a"},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)
		result := HashSHA256(tt.text)
		a.Equal(tt.expected, result, target)
	}
}

func TestHashHMAC(t *testing.T) {
	a := assert.New(t)
	invalidKey := "invalidKey"

	tests := []struct {
		text     string
		key      string
		expected string
	}{
		{"", "key1", "9d16e0b4956bce836cd71a9b138c37580977ab693c78df339ae0f9884fed282b"},
		{"a", "key1", "f2f2566cc3ef1ea506a62e40b4e07aa0e4ee4715700d02dc0bdeef81f3552a05"},
		{"a", "key2", "51cad6d6a262d5ba5f06d2c11c9c6e20a9f32b3c1fbe4e944b388001ae3313d8"},
		{"aaa", "key1", "18191cf23ba15ab92472c43299715184d19d3c1ac46cd3c6456d9c7f351f45db"},
		{"aaa", "key2", "658ad1bda83f11f60b7721a6749f03c1ae06bcc08b3a1ceac5ec6094444c80f4"},
		{"あいうえお", "key1", "d531fbeb88e37f76253523565fac83e627eea0644d61441c2127e55314faa04f"},
		{"あいうえお", "key2", "e762ef856e5955ebf048689e7c333250a33cbbf7d91e7a0ad1ee8710460b1d50"},
		{"a", "", "9615a95d4a336118c435b9cd54c5e8644ab956b573aa2926274a1280b6674713"},
		{"aaa", "", "37f34b80c6854f8908c748663793977390edbffaa4d2bc9722b40e1f2f45db61"},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)
		result := HashHMAC(tt.text, tt.key)
		a.Equal(tt.expected, result, target, "using valid key")

		result = HashHMAC(tt.text, invalidKey)
		a.NotEqual(tt.expected, result, target, "using invalid key")
	}
}
