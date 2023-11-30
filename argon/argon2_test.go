package argon

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var argonRegex = regexp.MustCompile(`^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[-A-Za-z0-9+/]+\$[-A-Za-z0-9+/]+$`)

func TestArgon2(t *testing.T) {
	t.Run("correct password", func(t *testing.T) {
		hash, err := GenerateFromPassword("password")
		require.NoError(t, err)

		assert.Regexp(t, argonRegex, hash)
		err = ValidatePassword("password", hash)
		assert.NoError(t, err)
	})

	t.Run("incorrect password", func(t *testing.T) {
		hash, err := GenerateFromPassword("password")
		require.NoError(t, err)

		assert.Regexp(t, argonRegex, hash)
		err = ValidatePassword("password1", hash)
		assert.ErrorIs(t, err, ErrWrongPassword)
	})

	t.Run("invalid hash", func(t *testing.T) {
		err := ValidatePassword("aa", "ksdjfkdsjfkdsjfdskfjdskfjdskfjkdf")
		assert.ErrorIs(t, err, ErrInvalidHash)
	})

}
