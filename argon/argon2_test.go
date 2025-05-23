package argon

import (
	"encoding/base64"
	"regexp"
	"testing"

	"github.com/spf13/viper"
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

func TestNeedsMigration(t *testing.T) {
	t.Run("bcrypt hash", func(t *testing.T) {
		assert.True(t, NeedsMigration("$2y$10$UKHA7gPNKpu/Kc7tyo91eudJZdX9qDs0S2E1GWgZKPkP/o4s2SR.m"))
	})

	t.Run("don't require migration if disabled", func(t *testing.T) {
		viper.Set("security.disable_migrate_on_login", true)
		t.Cleanup(func() {
			viper.Set("security.disable_migrate_on_login", false)
		})

		assert.False(t, NeedsMigration("$2y$10$UKHA7gPNKpu/Kc7tyo91eudJZdX9qDs0S2E1GWgZKPkP/o4s2SR.m"))
	})

	t.Run("don't require migration if argon props are correct", func(t *testing.T) {
		assert.False(t, NeedsMigration("$argon2id$v=19$m=65536,t=3,p=2$Sz1T6kOEN6fAa2/5NvHX5g$mDgZAJ7oLMYmW7yVAYnXBho7Ybg12woF66GQnP6XocA"))
	})

	t.Run("require migration if argon props are incorrect", func(t *testing.T) {
		assert.True(t, NeedsMigration("$argon2id$v=19$m=32768,t=4,p=2$doqbcsy6S669OpGN5twLfWm8mJjy6QywOJsPLnabTgs$zoyPNcenQg0H83J4EcX2QVLGJFAMkTXyg5Q8Rvt3qv0"))
	})
}

func TestDecodeHashParts(t *testing.T) {
	t.Run("happy case", func(t *testing.T) {
		memory, iterations, parallelism, salt, saltLen, hash, keyLen, err := decodeHashParts("$argon2id$v=19$m=32768,t=4,p=2$doqbcsy6S669OpGN5twLfWm8mJjy6QywOJsPLnabTgs$zoyPNcenQg0H83J4EcX2QVLGJFAMkTXyg5Q8Rvt3qv0")
		assert.NoError(t, err)

		assert.Equal(t, uint32(32768), memory)
		assert.Equal(t, uint32(4), iterations)
		assert.Equal(t, uint8(2), parallelism)
		assert.Equal(t, "doqbcsy6S669OpGN5twLfWm8mJjy6QywOJsPLnabTgs", base64.RawStdEncoding.Strict().EncodeToString(salt))
		assert.Equal(t, uint32(32), saltLen)
		assert.Equal(t, "zoyPNcenQg0H83J4EcX2QVLGJFAMkTXyg5Q8Rvt3qv0", base64.RawStdEncoding.Strict().EncodeToString(hash))
		assert.Equal(t, uint32(32), keyLen)
	})

	t.Run("invalid parallelism (too large)", func(t *testing.T) {
		_, _, _, _, _, _, _, err := decodeHashParts("$argon2id$v=19$m=32768,t=4,p=999$doqbcsy6S669OpGN5twLfWm8mJjy6QywOJsPLnabTgs$zoyPNcenQg0H83J4EcX2QVLGJFAMkTXyg5Q8Rvt3qv0")
		assert.Error(t, err)
	})

}

func TestArgonConfigInvalid(t *testing.T) {
	oldValue := viper.GetInt(ParallelismKey)
	viper.Set(ParallelismKey, 999)
	t.Cleanup(func() {
		viper.Set(ParallelismKey, oldValue)
	})

	_, err := GenerateFromPassword("abcdefg")
	assert.Error(t, err)
}
