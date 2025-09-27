package util

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindTrueIP(t *testing.T) {
	t.Run("fallback", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "1.2.3.4:5984",
		}

		assert.Equal(t, "1.2.3.4", FindTrueIP(r))
	})

	t.Run("x-forwarded-for", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "1.2.3.4:5892",
			Header:     map[string][]string{},
		}
		r.Header.Set("X-Forwarded-For", "192.168.2.1")

		assert.Equal(t, "192.168.2.1", FindTrueIP(r))
	})

	t.Run("x-forwarded-for (multiple)", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "1.2.3.4:5892",
			Header:     map[string][]string{},
		}
		r.Header.Set("X-Forwarded-For", "192.168.2.1, 999.999.999.999")

		assert.Equal(t, "192.168.2.1", FindTrueIP(r))
	})

	t.Run("x-real-ip", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "1.2.3.4:5892",
			Header:     map[string][]string{},
		}
		r.Header.Set("X-Real-Ip", "192.195.199.199")

		assert.Equal(t, "192.195.199.199", FindTrueIP(r))
	})

	t.Run("fallback order", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "1.2.3.4:5892",
			Header:     map[string][]string{},
		}
		r.Header.Set("X-Real-Ip", "192.195.199.199")
		r.Header.Set("X-Forwarded-For", "192.168.2.1, 999.999.999.999")

		assert.Equal(t, "192.195.199.199", FindTrueIP(r))
	})
}
