package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSetupCode(t *testing.T) {
	t.Run("produces a code of the expected shape", func(t *testing.T) {
		code, err := GenerateSetupCode()
		require.NoError(t, err)

		assert.Len(t, code, 26)
		assert.Equal(t, strings.ToUpper(code), code)
	})

	t.Run("generate codes randomly", func(t *testing.T) {
		seen := make(map[string]struct{})

		for range 500 {
			code, err := GenerateSetupCode()
			require.NoError(t, err)

			_, exists := seen[code]
			require.False(t, exists, "generated duplicate setup code %q", code)
			seen[code] = struct{}{}
		}
	})
}

func TestMiddleware_RoundTrip(t *testing.T) {
	t.Run("a written cookie decodes back to the same setup code", func(t *testing.T) {
		m := NewMiddleware("SETUPCODE")

		w := httptest.NewRecorder()
		require.NoError(t, m.WriteSession(w, "SETUPCODE"))

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)

		c := cookies[0]
		assert.Equal(t, FTUESessionCookieName, c.Name)
		assert.True(t, c.HttpOnly)
		assert.Equal(t, http.SameSiteStrictMode, c.SameSite)

		var s FTUESession
		require.NoError(t, m.sc.Decode(FTUESessionCookieName, c.Value, &s))
		assert.Equal(t, "SETUPCODE", s.SetupCode)
	})

	t.Run("the encoded value is opaque", func(t *testing.T) {
		m := NewMiddleware("SETUPCODE")

		encoded, err := m.EncodeValidCookie("SETUPCODE")
		require.NoError(t, err)

		assert.NotContains(t, encoded, "SETUPCODE")
	})

	t.Run("keys are randomly generated on middleware init", func(t *testing.T) {
		a := NewMiddleware("SETUPCODE")
		b := NewMiddleware("SETUPCODE")

		encoded, err := a.EncodeValidCookie("SETUPCODE")
		require.NoError(t, err)

		var s FTUESession
		assert.Error(t, b.sc.Decode(FTUESessionCookieName, encoded, &s), "cookie from one instance must not decode in another")
	})
}
