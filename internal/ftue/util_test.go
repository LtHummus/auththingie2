package ftue

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetRootDomain(t *testing.T) {
	t.Run("plain domains", func(t *testing.T) {
		assert.Equal(t, "example.com", GetRootDomain("example.com"))
		assert.Equal(t, "example.com", GetRootDomain("test.example.com"))
		assert.Equal(t, "example.biz", GetRootDomain("test.example.biz"))
		assert.Equal(t, "example.quix", GetRootDomain("foo.bar.example.quix"))
	})

	t.Run("strips the port", func(t *testing.T) {
		assert.Equal(t, "bar.example", GetRootDomain("foo.bar.example:9000"))
		assert.Equal(t, "localhost", GetRootDomain("localhost:9000"))
		assert.Equal(t, "example.com", GetRootDomain("test.example.com:8443"))
	})

	t.Run("handles multi label public suffixes", func(t *testing.T) {
		assert.Equal(t, "example.co.uk", GetRootDomain("test.example.co.uk"))
		assert.Equal(t, "example.github.io", GetRootDomain("shop.example.github.io"))
	})

	t.Run("passes through single label hosts", func(t *testing.T) {
		assert.Equal(t, "localhost", GetRootDomain("localhost"))
		assert.Equal(t, "auth", GetRootDomain("auth"))
	})

	t.Run("normalizes case and a trailing dot", func(t *testing.T) {
		assert.Equal(t, "example.com", GetRootDomain("TEST.EXAMPLE.COM"))
		assert.Equal(t, "example.com", GetRootDomain("test.example.com."))
	})

	t.Run("returns nothing for an IP address", func(t *testing.T) {
		assert.Equal(t, "", GetRootDomain("127.0.0.1"))
		assert.Equal(t, "", GetRootDomain("127.0.0.1:56355"))
		assert.Equal(t, "", GetRootDomain("192.168.1.10"))
		assert.Equal(t, "", GetRootDomain("[fd00::1]:9000"))
		assert.Equal(t, "", GetRootDomain("fd00::1"))
	})
}

func TestIsIPAddress(t *testing.T) {
	for _, curr := range []string{"127.0.0.1", "127.0.0.1:9000", "192.168.1.10", "fd00::1", "[fd00::1]", "[fd00::1]:9000", "::1"} {
		assert.True(t, isIPAddress(curr), "%q should be detected as an IP", curr)
	}

	for _, curr := range []string{"example.com", "test.example.com", "example.com:9000", "localhost", "localhost:9000", "auth"} {
		assert.False(t, isIPAddress(curr), "%q should not be detected as an IP", curr)
	}
}

func buildOriginFormRequest(host string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/ftue/step0", nil)
	r.Host = host
	return r
}

func TestRequestHost(t *testing.T) {
	t.Run("falls back to r.Host when unproxied", func(t *testing.T) {
		assert.Equal(t, "auth.example.com", RequestHost(buildOriginFormRequest("auth.example.com")))
	})

	t.Run("prefers X-Forwarded-Host over the internal host", func(t *testing.T) {
		r := buildOriginFormRequest("auththingie2:9000")
		r.Header.Set(forwardedHostHeader, "auth.example.com")

		assert.Equal(t, "auth.example.com", RequestHost(r))
	})

	t.Run("takes the leftmost element of a proxy chain", func(t *testing.T) {
		r := buildOriginFormRequest("auththingie2:9000")
		r.Header.Set(forwardedHostHeader, "auth.example.com, inner.proxy")

		assert.Equal(t, "auth.example.com", RequestHost(r))
	})

	t.Run("takes the last header instance", func(t *testing.T) {
		r := buildOriginFormRequest("auththingie2:9000")
		r.Header.Add(forwardedHostHeader, "spoofed.example.com")
		r.Header.Add(forwardedHostHeader, "auth.example.com")

		assert.Equal(t, "auth.example.com", RequestHost(r))
	})
}

func TestRequestOrigin(t *testing.T) {
	t.Run("defaults to https on a plain origin form request", func(t *testing.T) {
		// this is the case a real server always hits, and the one that regressed
		origin := RequestOrigin(buildOriginFormRequest("auth.example.com"))

		assert.Equal(t, "https://auth.example.com", origin)
		assert.False(t, strings.HasPrefix(origin, "://"), "origin must never start with a bare ://")
	})

	t.Run("honors X-Forwarded-Proto", func(t *testing.T) {
		r := buildOriginFormRequest("auth.example.com")
		r.Header.Set(forwardedProtoHeader, "http")

		assert.Equal(t, "http://auth.example.com", RequestOrigin(r))
	})

	t.Run("is case insensitive and tolerates whitespace", func(t *testing.T) {
		r := buildOriginFormRequest("auth.example.com")
		r.Header.Set(forwardedProtoHeader, "  HTTP ")

		assert.Equal(t, "http://auth.example.com", RequestOrigin(r))
	})

	t.Run("takes the leftmost proto in a proxy chain", func(t *testing.T) {
		r := buildOriginFormRequest("auth.example.com")
		r.Header.Set(forwardedProtoHeader, "https, http")

		assert.Equal(t, "https://auth.example.com", RequestOrigin(r))
	})

	t.Run("combines forwarded proto and host", func(t *testing.T) {
		r := buildOriginFormRequest("auththingie2:9000")
		r.Header.Set(forwardedProtoHeader, "http")
		r.Header.Set(forwardedHostHeader, "auth.example.com")

		assert.Equal(t, "http://auth.example.com", RequestOrigin(r))
	})

	t.Run("rejects a scheme outside the allowlist", func(t *testing.T) {
		for _, bogus := range []string{"javascript", "", "ftp", "gopher", "http://evil"} {
			r := buildOriginFormRequest("auth.example.com")
			r.Header.Set(forwardedProtoHeader, bogus)

			assert.Equal(t, "https://auth.example.com", RequestOrigin(r), "proto %q should fall back to https", bogus)
		}
	})

	t.Run("output always survives validateURL", func(t *testing.T) {
		for _, proto := range []string{"", "http", "https", "javascript", "HTTPS , http"} {
			r := buildOriginFormRequest("auth.example.com")
			if proto != "" {
				r.Header.Set(forwardedProtoHeader, proto)
			}

			assert.NoError(t, validateURL(RequestOrigin(r)), "prefill for proto %q must pass its own validator", proto)
		}
	})
}
