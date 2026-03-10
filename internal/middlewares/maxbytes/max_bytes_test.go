package maxbytes

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_ServeHTTP(t *testing.T) {
	t.Run("error on large request body", func(t *testing.T) {
		fakeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := io.ReadAll(r.Body)
			var mbe *http.MaxBytesError
			assert.ErrorAs(t, err, &mbe)
		})

		m := NewMaxBytesMiddleware(fakeHandler, 5)

		recorder := httptest.NewRecorder()
		req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, "/", strings.NewReader("aaaaaaaaaa"))
		require.NoError(t, err)

		m.ServeHTTP(recorder, req)

		resp := recorder.Result()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("successfully read on shorter bodies", func(t *testing.T) {
		fakeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fullBody, err := io.ReadAll(r.Body)
			require.NoError(t, err)

			assert.Len(t, fullBody, 5)
			w.WriteHeader(http.StatusOK)
		})

		m := NewMaxBytesMiddleware(fakeHandler, 100)

		recorder := httptest.NewRecorder()
		req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, "/", strings.NewReader("aaaaa"))
		require.NoError(t, err)

		m.ServeHTTP(recorder, req)

		resp := recorder.Result()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
