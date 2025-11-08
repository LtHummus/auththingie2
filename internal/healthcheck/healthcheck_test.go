package healthcheck

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCheckHealth(t *testing.T) {
	t.Run("basic case (200)", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/", r.URL.Path)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		err := CheckHealth(srv.URL, 5*time.Second, false)
		assert.NoError(t, err)
	})

	t.Run("basic case (302)", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/", r.URL.Path)
			w.WriteHeader(http.StatusFound)
		}))
		defer srv.Close()

		err := CheckHealth(srv.URL, 5*time.Second, false)
		assert.NoError(t, err)
	})

	t.Run("base case (200) w/ TLS", func(t *testing.T) {
		called := false

		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		srv.TLS = &tls.Config{}
		srv.StartTLS()
		defer srv.Close()

		// replace client with one that will accept the generated certs, then swap back when the test is complete
		client = srv.Client()

		t.Cleanup(func() {
			client = &http.Client{}
		})

		err := CheckHealth(srv.URL, 5*time.Second, false)
		assert.NoError(t, err)

		assert.True(t, called)
	})

	t.Run("unhealthy service", func(t *testing.T) {
		called := false

		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusInternalServerError)
		}))
		srv.TLS = &tls.Config{}
		srv.StartTLS()
		defer srv.Close()

		// replace client with one that will accept the generated certs, then swap back when the test is complete
		client = srv.Client()

		t.Cleanup(func() {
			client = &http.Client{}
		})

		err := CheckHealth(srv.URL, 5*time.Second, false)
		assert.Error(t, err)

		assert.True(t, called)
	})

	t.Run("fail test if bad cert and we haven't told to ignore", func(t *testing.T) {
		called := false
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		srv.StartTLS()
		defer srv.Close()

		err := CheckHealth(srv.URL, 5*time.Second, false)
		assert.Error(t, err)
		assert.False(t, called)
	})

	t.Run("ignore bad cert if we need to", func(t *testing.T) {
		called := false
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		srv.StartTLS()
		defer srv.Close()

		err := CheckHealth(srv.URL, 5*time.Second, true)
		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("handle timeout", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(3 * time.Second)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		err := CheckHealth(srv.URL, 1*time.Second, false)
		assert.Error(t, err)
	})
}
