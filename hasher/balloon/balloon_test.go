package balloon

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBalloon_Hash(t *testing.T) {
	a := assert.New(t)
	invalidKey := "invalidKey"

	tests := []struct {
		text     string
		key      string
		expected string
	}{
		{"", "key1", "a8bebaf28e9052d9dc4c664ce57a18fb9be8c07cdac3df7e949af23a18d4fe1d5a7957b44388e2555367592cc3508fdb44d0604345da2e3696b1eb86b1dfce1f"},
		{"a", "key1", "6f4a0ab4e460ea15eac1539219f79cdb79612df4318153f1de6afee647022e8a0f033ca6fba030d0356c9dc96dfcac1824097e508b2af16f00bac2d90cd31cbb"},
		{"a", "key2", "75b058799b00e687332905a3d72ae9c222c745cd06cbdd90fd2dfcc566be144a53b1434e9abeef5f0e1a56186617137819e3c932dbdebea18fbec20b898e1617"},
		{"aaa", "key1", "b9e76f2e683f18387eff196676404bbcfe36d5219e031dd0edf9b4d23f394d9a1c53e4d6e0c5bb5b41ffe730c631beb11a68b21b8065302c62cb02a60cdfbbc6"},
		{"aaa", "key2", "0b3b53b53648da7731e043ab1dbb2f6d9888c4a57ce0400b23c3e82953cf8ef74e3e50b11e951c80f7a081cce163aa900bf502d891b10fca2162649552346f1f"},
		{"あいうえお", "key1", "3689065173dab6936a11fd0ff3d239aa1752f5272680a66cdc3f8feff04d2cd58c243aaa862bc3527410cb5f8de98d51854ac079bfe461f51ea61c04e84c6be7"},
		{"あいうえお", "key2", "ccadf5b1ee45fc09fc0520b8c21d2ac97c8dadc31b53080a1131ce75a0256c7840189c2d6a14b59aed78e620e885392d6b37726e2b36f0b3f63c3b444c4258ca"},
		{"a", "", "b5feba83571ddd6f8eba320a68ff3fad49840ed49268a183d0680bede9bb8ac81b7ee441b0aa4befd14c5f5eddc494da517760ead8dcc489c6477af809cd4410"},
		{"aaa", "", "fdab8dc70e81a86d85f4fbc509bac4384bf58942a5c220ba30679903f11b5ceefc8ad3dfcc047c01ad211a559d1f534996136893a3c02c1707be42719020d78d"},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)

		b := Balloon{}
		result := b.Hash(tt.text, tt.key)
		a.Equal(tt.expected, result, target, "using valid key")

		result = b.Hash(tt.text, invalidKey)
		a.NotEqual(tt.expected, result, target, "using invalid key")
	}
}
