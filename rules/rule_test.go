package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInternalMatch(t *testing.T) {
	assert.True(t, internalMatch("abc", "abc"))
	assert.True(t, internalMatch("a", "a"))

	assert.True(t, internalMatch("*", "abcdefg"))
	assert.True(t, internalMatch("a*", "abc"))
	assert.False(t, internalMatch("a*", "babc"))

	assert.True(t, internalMatch("a?c", "abc"))
	assert.True(t, internalMatch("a??", "abc"))
}
