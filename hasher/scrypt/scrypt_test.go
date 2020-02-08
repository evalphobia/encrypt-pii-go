package scrypt

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSCrypt_Hash(t *testing.T) {
	a := assert.New(t)
	invalidKey := "invalidKey"

	tests := []struct {
		text     string
		key      string
		expected string
	}{
		{"", "key1", "5e2014827cd43c16b7a054a7574738b37f9a707c3f9fcf83ed0cf851cb6b3b13"},
		{"a", "key1", "5f27b7edac3695e256254f07930a1eeb2c9a7b918545cc12ea1d7a127662ea80"},
		{"a", "key2", "e578acc9bb4fbdbd4f71e2a41fd8cb0b4202ba1683c80763666c97f53a4af0cb"},
		{"aaa", "key1", "e0e914278d6bda1756361bdf13739ad84b565f0cc97969331a56c455e8787d8f"},
		{"aaa", "key2", "93d91fc419cb83db242cbe9db3c3d2e6778c723a98bf5f40afa9af16472a97b2"},
		{"あいうえお", "key1", "5f0356c032b8ff5d8aceb6d9bf0f7a56b8b307b6a674a8df6fcefc347336a6ae"},
		{"あいうえお", "key2", "86ab3a3de08a8b2d47998115f31634bc088acb15be6d1efa58c441db409eabaa"},
		{"a", "", "be3abcca6dd77bf5ea23168f6b94078aa7e8792471aeac2b277206b642e576ea"},
		{"aaa", "", "26725b51151d2bfdabb5e74275a43f45669e4971cae99af2765ebe1623c08d0a"},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)

		b := SCrypt{}
		result := b.Hash(tt.text, tt.key)
		a.Equal(tt.expected, result, target, "using valid key")

		result = b.Hash(tt.text, invalidKey)
		a.NotEqual(tt.expected, result, target, "using invalid key")
	}
}
