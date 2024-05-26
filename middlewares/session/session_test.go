package session

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lthummus/auththingie2/user"
)

func TestNewDefaultSession(t *testing.T) {
	s, err := NewDefaultSession()
	assert.NoError(t, err)

	assert.WithinDuration(t, time.Now(), s.CreationTime, 1*time.Second)
	assert.Equal(t, map[string]any{}, s.CustomData)
	assert.Empty(t, s.UserID)
	assert.WithinDuration(t, time.Now().Add(DefaultSessionLifetime), s.Expires, 1*time.Second)

	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(s.SessionID)
	require.NoError(t, err)

	require.Len(t, decoded, IDLengthBytes)
}

func TestSession_Expired(t *testing.T) {
	s, err := NewDefaultSession()
	require.NoError(t, err)

	s.Expires = time.Now().Add(-1 * time.Hour)

	assert.True(t, s.Expired())
}

func TestSession_PlaceUserInSession(t *testing.T) {
	t.Run("basic case", func(t *testing.T) {
		s, err := NewDefaultSession()
		require.NoError(t, err)

		s.PlaceUserInSession(&user.User{
			Username: "foo",
			Id:       "1234",
		})

		assert.Equal(t, "1234", s.UserID)
		assert.WithinDuration(t, time.Now().Add(DefaultSessionLifetime), s.Expires, 1*time.Second)
		assert.WithinDuration(t, time.Now(), s.CreationTime, 1*time.Second)
	})

	t.Run("panic on disabled user", func(t *testing.T) {
		s, err := NewDefaultSession()
		require.NoError(t, err)

		u := &user.User{
			Username: "foo",
			Id:       "1234",
			Disabled: true,
		}

		assert.Panics(t, func() {
			s.PlaceUserInSession(u)
		})
	})
}
