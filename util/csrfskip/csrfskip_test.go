package csrfskip

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSkipper(t *testing.T) {
	s := NewSkipper([]string{"/foo", "/bar"})

	assert.NotNil(t, s)
}

func TestSkipper_ServeHTTP(t *testing.T) {
	t.Run("basic functionality", func(t *testing.T) {
		s := NewSkipper([]string{"/foo", "/bar"})

		calls := 0
		skips := 0

		h := s(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls += 1
			if r.Context().Value("gorilla.csrf.Skip") == true {
				skips += 1
			}
		}))

		r := httptest.NewRequest(http.MethodPost, "/static/foo.js", nil)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, r)

		assert.Equal(t, 1, calls)
		assert.Equal(t, 1, skips)

		r = httptest.NewRequest(http.MethodPost, "/check", nil)
		w = httptest.NewRecorder()

		h.ServeHTTP(w, r)

		assert.Equal(t, 2, calls)
		assert.Equal(t, 1, skips)

		r = httptest.NewRequest(http.MethodPost, "/foo", nil)
		w = httptest.NewRecorder()

		h.ServeHTTP(w, r)

		assert.Equal(t, 3, calls)
		assert.Equal(t, 2, skips)

		r = httptest.NewRequest(http.MethodPost, "/bar", nil)
		w = httptest.NewRecorder()

		h.ServeHTTP(w, r)

		assert.Equal(t, 4, calls)
		assert.Equal(t, 3, skips)

	})
}
