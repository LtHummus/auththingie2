package redirects

import (
	"fmt"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withAllowedDomains(domains []string) configFunc {
	return func(v *viper.Viper) {
		v.Set(AllowedDomainsKey, domains)
	}
}

func withAllowedDomain(domain string) configFunc {
	return func(v *viper.Viper) {
		d := v.GetStringSlice(AllowedDomainsKey)
		d = append(d, domain)
		v.Set(AllowedDomainsKey, d)
	}
}

func withAllowAll() configFunc {
	return func(v *viper.Viper) {
		v.Set(AllowAllKey, true)
	}
}

func withServerDomain(domain string) configFunc {
	return func(v *viper.Viper) {
		v.Set(ServerDomainKey, domain)
	}
}

func withFallbackURL(fallbackURL string) configFunc {
	return func(v *viper.Viper) {
		v.Set(FallbackURLKey, fallbackURL)
	}
}

type configFunc func(v *viper.Viper)

func buildConfig(opts ...configFunc) *viper.Viper {
	v := viper.New()
	for _, curr := range opts {
		curr(v)
	}

	return v
}

func TestViperValidator_IsAllowed(t *testing.T) {
	t.Run("basic test for backwards compatibility", func(t *testing.T) {
		cfg := buildConfig(withServerDomain("example.com"))
		v, err := NewFromConfig(cfg)
		require.NoError(t, err)

		assert.True(t, v.IsAllowed("https://example.com"))
		assert.True(t, v.IsAllowed("https://foo.example.com"))
		assert.True(t, v.IsAllowed("https://bar.foo.example.com"))
		assert.True(t, v.IsAllowed("http://example.com"))
		assert.True(t, v.IsAllowed("http://example.com."))
		assert.True(t, v.IsAllowed("ftp://example.com"))

		assert.False(t, v.IsAllowed("https://otherexample.com"))
		assert.False(t, v.IsAllowed("https://evilsite"))
		assert.False(t, v.IsAllowed("/"))
		assert.False(t, v.IsAllowed(""))
		assert.False(t, v.IsAllowed("//example.com"))
		assert.False(t, v.IsAllowed("https://example.com@bad.com"))
	})

	t.Run("corretly trim trailing suffix on allowed domains", func(t *testing.T) {
		cfg := buildConfig(withServerDomain("example.com."))
		v, err := NewFromConfig(cfg)
		require.NoError(t, err)

		assert.True(t, v.IsAllowed("https://example.com"))
	})

	t.Run("test for subdomains", func(t *testing.T) {
		cfg := buildConfig(withAllowedDomain("foo.example.com"))
		v, err := NewFromConfig(cfg)
		require.NoError(t, err)

		assert.True(t, v.IsAllowed("https://foo.example.com"))
		assert.True(t, v.IsAllowed("https://aaa.foo.example.com"))
		assert.True(t, v.IsAllowed("https://bbb.foo.example.com"))

		assert.False(t, v.IsAllowed("https://example.com"))
	})

	t.Run("test with two allowed domains", func(t *testing.T) {
		cfg := buildConfig(withAllowedDomains([]string{"foo.com", "bar.com"}))
		v, err := NewFromConfig(cfg)
		require.NoError(t, err)

		assert.True(t, v.IsAllowed("https://foo.com"))
		assert.True(t, v.IsAllowed("https://bar.com"))
		assert.False(t, v.IsAllowed("https://example.com"))
	})

	t.Run("unicode domain", func(t *testing.T) {
		cfg := buildConfig(withAllowedDomain("😭.com"))
		v, err := NewFromConfig(cfg)
		require.NoError(t, err)

		assert.True(t, v.IsAllowed("https://😭.com"))
		assert.True(t, v.IsAllowed("https://xn--o38h.com")) // punycode encoded version
		assert.True(t, v.IsAllowed("https://foo.😭.com"))
		assert.False(t, v.IsAllowed("https://😘.com"))
	})

	t.Run("set domains should override the server.domain", func(t *testing.T) {
		cfg := buildConfig(withServerDomain("example.com"), withAllowedDomain("foo.com"))
		v, err := NewFromConfig(cfg)
		require.NoError(t, err)

		assert.True(t, v.IsAllowed("https://foo.com"))
		assert.False(t, v.IsAllowed("https://example.com"))
	})

	t.Run("allow all ... allows all", func(t *testing.T) {
		cfg := buildConfig(withAllowAll())
		v, err := NewFromConfig(cfg)
		require.NoError(t, err)

		assert.True(t, v.IsAllowed("https://example.com"))
		assert.True(t, v.IsAllowed("https://foo.example.com"))
		assert.True(t, v.IsAllowed("https://bar.foo.example.com"))
		assert.True(t, v.IsAllowed("http://example.com"))
		assert.True(t, v.IsAllowed("https://otherexample.com"))
		assert.True(t, v.IsAllowed("https://evilsite"))
		assert.True(t, v.IsAllowed("/"))
		assert.True(t, v.IsAllowed(""))
		assert.True(t, v.IsAllowed("//example.com"))
	})
}

func TestViperValidator_Sanitize(t *testing.T) {
	t.Run("basic test", func(t *testing.T) {
		cfg := buildConfig(withServerDomain("example.com"), withFallbackURL("https://fallback.example.com"))
		v, err := NewFromConfig(cfg)
		require.NoError(t, err)

		tests := []struct {
			input     string
			outputURL string
			sanitized bool
		}{
			{
				input:     "https://example.com",
				outputURL: "https://example.com",
				sanitized: false,
			},
			{
				input:     "https://foo.example.com",
				outputURL: "https://foo.example.com",
				sanitized: false,
			},
			{
				input:     "https://bar.foo.example.com",
				outputURL: "https://bar.foo.example.com",
				sanitized: false,
			},
			{
				input:     "http://example.com",
				outputURL: "http://example.com",
				sanitized: false,
			},
			{
				input:     "https://otherexample.com",
				outputURL: "https://fallback.example.com",
				sanitized: true,
			},
			{
				input:     "https://evilsite",
				outputURL: "https://fallback.example.com",
				sanitized: true,
			},
			{
				input:     "/",
				outputURL: "https://fallback.example.com",
				sanitized: true,
			},
			{
				input:     "",
				outputURL: "https://fallback.example.com",
				sanitized: true,
			},
			{
				input:     "//example.com",
				outputURL: "https://fallback.example.com",
				sanitized: true,
			},
		}

		for _, curr := range tests {
			t.Run(fmt.Sprintf("test %s", curr.input), func(t *testing.T) {
				sanitizedURL, wasSanitized := v.Sanitize(curr.input)
				assert.Equal(t, curr.outputURL, sanitizedURL)
				assert.Equal(t, curr.sanitized, wasSanitized)
			})
		}

	})
}
