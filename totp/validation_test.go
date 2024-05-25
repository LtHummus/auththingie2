package totp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginTicket(t *testing.T) {
	setupSalts(t)

	t.Run("generate a ticket", func(t *testing.T) {
		lt := GenerateLoginTicket("aaa", "bbbb")
		assert.Equal(t, "aaa", lt.UserID)
		assert.Equal(t, "bbbb", lt.RedirectURI)
		assert.WithinDuration(t, time.Now().Add(5*time.Minute), lt.Expiration, time.Second)
	})

	t.Run("generate, encode and then decode", func(t *testing.T) {
		lt := GenerateLoginTicket("abcdefg", "https://example.com")

		encoded, err := lt.Encode()
		require.NoError(t, err)

		decoded, err := DecodeLoginTicket(encoded)
		require.NoError(t, err)

		assert.Equal(t, "abcdefg", decoded.UserID)
		assert.Equal(t, "https://example.com", decoded.RedirectURI)
		assert.WithinDuration(t, time.Now().Add(5*time.Minute), decoded.Expiration, time.Second)
	})

	t.Run("fail to decode a non-login ticket", func(t *testing.T) {
		et := GenerateEnrollmentTicket("sampleuser", "AAAAAAA")
		encoded, err := et.Encode()
		require.NoError(t, err)

		_, err = DecodeLoginTicket(encoded)
		assert.Error(t, err)
	})
}
