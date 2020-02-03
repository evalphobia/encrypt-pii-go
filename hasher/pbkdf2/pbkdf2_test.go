package pbkdf2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPBKDF2_Hash(t *testing.T) {
	a := assert.New(t)
	invalidKey := "invalidKey"

	tests := []struct {
		text     string
		key      string
		expected string
	}{
		{"", "key1", "ec87b6178de8636a225912274c83eff4c4bf6276ce4ac865294d47aa7687c695"},
		{"a", "key1", "27dd50227bd72e83cc5733f4603c9d2dbdb960d618361d5c096e3c484be1a87f"},
		{"a", "key2", "4a46e6dd0440ca4ef47810af9d57fb8ec8d20beee3c281c82244720224006e9c"},
		{"aaa", "key1", "db23b4a5e3c3156d1f6543389e1e147043f1a13ae153771046fdd81dd79843a4"},
		{"aaa", "key2", "648a7337aed49b50d190979d51ec547ffb0138c4d6b4508462f70ccf6cda6465"},
		{"あいうえお", "key1", "41c6f9d68e07f9f3487cffd1e67edf02f2e2d748145c75a8bacd811a59a8b30e"},
		{"あいうえお", "key2", "74f2917a235948f5436c0e82721fe4cc72ea557ef0ff9479750ad6e3ad7da34f"},
		{"a", "", "abdcaa1a2c12ceede21573ddf1fbab70e15dee82f123fa283d2f3c57a797dbff"},
		{"aaa", "", "8db8c599743059407684ebcc03fb9121b7c32529114b4a46c5f8fb3f6e040093"},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)

		b := PBKDF2{}
		result := b.Hash(tt.text, tt.key)
		a.Equal(tt.expected, result, target, "using valid key")

		result = b.Hash(tt.text, invalidKey)
		a.NotEqual(tt.expected, result, target, "using invalid key")
	}
}
