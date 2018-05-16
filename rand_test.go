package hierogolyph

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetRandomBytes(t *testing.T) {
	a := assert.New(t)

	tests := []struct {
		size int
	}{
		{0},
		{1},
		{2},
		{10},
		{100},
		{1000},
		{10000},
		{100000},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)

		result, err := getRandomBytes(tt.size)
		a.NoError(err, target)
		a.Len(result, tt.size, target)
	}
}

func TestGetRandomString(t *testing.T) {
	a := assert.New(t)

	tests := []struct {
		size int
	}{
		{0},
		{1},
		{2},
		{10},
		{100},
		{1000},
		{10000},
		{100000},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%+v", tt)

		result, err := getRandomString(tt.size)
		a.NoError(err, target)
		a.Len(result, tt.size, target)
	}

	// confirm all the letter is appeared.
	result, err := getRandomString(100000)
	a.NoError(err)
	for _, letter := range letters {
		l := string(letter)
		a.Contains(result, l, "cannot find the letter in result", l)
	}
}
