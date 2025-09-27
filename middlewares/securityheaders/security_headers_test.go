package securityheaders

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_ServeHTTP(t *testing.T) {
	fakeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Hello world!"))
	})

	m := NewSecurityHeadersMiddleware(fakeHandler)

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, "/", nil)
	require.NoError(t, err)

	m.ServeHTTP(recorder, req)

	resp := recorder.Result()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "Hello world!", recorder.Body.String())
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "strict-origin-when-cross-origin", resp.Header.Get("Referrer-Policy"))
	assert.Equal(t, "default-src 'self'", resp.Header.Get("Content-Security-Policy"))
}
