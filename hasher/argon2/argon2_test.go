package argon2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArgon2_Hash(t *testing.T) {
	a := assert.New(t)
	invalidKey := "invalidKey"

	tests := []struct {
		text     string
		key      string
		expected string
	}{
		{"", "key1", "935c761f2910d08b7b1b452b4976c533c1a629e5be1bf788053d264992f8ff9f"},
		{"a", "key1", "2e6be3ddf1d3c49e0289ffb1c1e0c9c66f0c8e4aac2653c902e6642f842bbdec"},
		{"a", "key2", "6c77ad5d7a75e0d1324d0714ec8c7eedb9eb19364bb9ec4f90eb0878581aad7d"},
		{"aaa", "key1", "235a63e8d7a81420ac8b121d2ba5161016ca5224806c50f1c3eb9c391a319665"},
		{"aaa", "key2", "d8a501abff84d2c313636dbc261769cedc5e98569674099ef7e7e86e980ef46a"},
		{"あいうえお", "key1", "0e3ce6e71f84df02413e000596cb0f27ecd8b23505e2f85c9466255e7c04b25b"},
		{"あいうえお", "key2", "9dd5183f1745dbcc84ea040bb7ed62479d30d16956982c59dd0ea97fe7433415"},
		{"a", "", "8553444959f72faefc9b19288c8057ebf86591a59644761d0954c53b8ea9905b"},
		{"aaa", "", "3b9c3959d45fc8f4741eea27638a8298dde57e415cb67f19cb62f5fea6e11e86"},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)

		argon := Argon2{}
		result := argon.Hash(tt.text, tt.key)
		a.Equal(tt.expected, result, target, "using valid key")

		result = argon.Hash(tt.text, invalidKey)
		a.NotEqual(tt.expected, result, target, "using invalid key")

		argon = Argon2{
			Time: defaultArgon2Time * 2,
		}
		result = argon.Hash(tt.text, tt.key)
		a.NotEqual(tt.expected, result, target, "double time")

		argon = Argon2{
			Memory: defaultArgon2Memory * 2,
		}
		result = argon.Hash(tt.text, tt.key)
		a.NotEqual(tt.expected, result, target, "double memory")

		argon = Argon2{
			Threads: defaultArgon2Threads * 2,
		}
		result = argon.Hash(tt.text, tt.key)
		a.NotEqual(tt.expected, result, target, "double threads")

		argon = Argon2{
			KeyLength: defaultArgon2KeyLength * 2,
		}
		result = argon.Hash(tt.text, tt.key)
		a.NotEqual(tt.expected, result, target, "double key length")
	}
}
