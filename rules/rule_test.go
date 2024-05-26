package rules

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInternalMatch(t *testing.T) {
	assert.True(t, internalMatch("abc", "abc"))
	assert.True(t, internalMatch("a", "a"))

	assert.True(t, internalMatch("*", "abcdefg"))
	assert.True(t, internalMatch("a*", "abc"))
	assert.False(t, internalMatch("a*", "babc"))

	assert.True(t, internalMatch("a?c", "abc"))
	assert.True(t, internalMatch("a??", "abc"))

	assert.False(t, internalMatch("a??", "ab"))
}

func TestRule_New(t *testing.T) {
	t.Run("fully defined rule", func(t *testing.T) {
		v := viper.New()
		v.Set("name", "test rule")
		v.Set("source", "192.168.0.0/16")
		v.Set("protocol_pattern", "https")
		v.Set("host_pattern", "example.com")
		v.Set("path_pattern", "/foo")
		v.Set("timeout", "5m")
		v.Set("public", false)
		v.Set("roles", []string{"a", "b"})

		r, err := New(v)
		require.NoError(t, err)

		_, s, _ := net.ParseCIDR("192.168.0.0/16")

		assert.Equal(t, "test rule", r.Name)
		assert.Equal(t, s, r.SourceAddress)
		assert.Equal(t, "https", *r.ProtocolPattern)
		assert.Equal(t, "example.com", *r.HostPattern)
		assert.Equal(t, "/foo", *r.PathPattern)
		assert.Equal(t, 5*time.Minute, *r.Timeout)
		assert.Equal(t, false, r.Public)
		assert.Equal(t, []string{"a", "b"}, r.PermittedRoles)
	})

	t.Run("error on invalid CIDR", func(t *testing.T) {
		v := viper.New()
		v.Set("name", "test rule")
		v.Set("source", "aaaaaaaaa")
		v.Set("host_pattern", "example.com")
		v.Set("path_pattern", "/foo")

		r, err := New(v)
		assert.Nil(t, r)
		assert.Error(t, err)
	})

	t.Run("without timeout", func(t *testing.T) {
		v := viper.New()
		v.Set("name", "test rule")
		v.Set("host_pattern", "example.com")

		r, err := New(v)
		assert.NoError(t, err)

		assert.Equal(t, "test rule", r.Name)
		assert.Equal(t, "example.com", *r.HostPattern)
		assert.Empty(t, r.PathPattern)
		assert.Empty(t, r.ProtocolPattern)
		assert.Empty(t, r.SourceAddress)
		assert.Empty(t, r.Timeout)
	})
}

func TestRule_Matches(t *testing.T) {
	ri := &RequestInfo{
		Method:     http.MethodGet,
		Protocol:   "https",
		Host:       "example.com",
		RequestURI: "/foo",
		SourceIP:   net.ParseIP("192.168.1.1"),
	}

	_, internalNetwork, _ := net.ParseCIDR("192.168.0.0/16")
	_, otherNetwork, _ := net.ParseCIDR("10.0.0.0/8")
	protocol := "https"
	protocol2 := "http"
	host := "example.com"
	host2 := "example.net"
	requestURI := "/foo"
	requestURI2 := "/bar"

	t.Run("various matches", func(t *testing.T) {
		r := &Rule{
			SourceAddress:   internalNetwork,
			ProtocolPattern: &protocol,
			HostPattern:     &host,
			PathPattern:     &requestURI,
		}

		assert.True(t, r.Matches(ri))

		r.ProtocolPattern = &protocol2
		assert.False(t, r.Matches(ri))

		r.ProtocolPattern = &protocol
		r.HostPattern = &host2
		assert.False(t, r.Matches(ri))

		r.HostPattern = &host
		r.PathPattern = &requestURI2
		assert.False(t, r.Matches(ri))

		r.PathPattern = &requestURI
		r.SourceAddress = otherNetwork
		assert.False(t, r.Matches(ri))
	})

}

func TestRule_toRawRule(t *testing.T) {
	_, internalNetwork, _ := net.ParseCIDR("192.168.0.0/16")
	protocol := "https"
	host := "example.com"
	requestURI := "/foo"

	t.Run("completely defined rule", func(t *testing.T) {
		r := &Rule{
			Name:            "test rule",
			SourceAddress:   internalNetwork,
			ProtocolPattern: &protocol,
			HostPattern:     &host,
			PathPattern:     &requestURI,
			Public:          false,
			PermittedRoles:  []string{"a", "b"},
		}

		rr := r.toRawRule()

		assert.Equal(t, "test rule", rr.Name)
		assert.Equal(t, "192.168.0.0/16", *rr.SourceAddress)
		assert.Equal(t, "https", *rr.ProtocolPattern)
		assert.Equal(t, "example.com", *rr.HostPattern)
		assert.Equal(t, "/foo", *rr.PathPattern)
		assert.Equal(t, false, rr.Public)
		assert.Equal(t, []string{"a", "b"}, rr.PermittedRoles)
	})

	t.Run("some things left undefined", func(t *testing.T) {
		r := &Rule{
			Name:           "a second rule",
			HostPattern:    &host,
			Public:         false,
			PermittedRoles: []string{"a"},
		}

		rr := r.toRawRule()

		assert.Equal(t, "a second rule", rr.Name)
		assert.Nil(t, rr.SourceAddress)
		assert.Nil(t, rr.ProtocolPattern)
		assert.Equal(t, "example.com", *rr.HostPattern)
		assert.Nil(t, rr.PathPattern)
		assert.Equal(t, false, rr.Public)
		assert.Equal(t, []string{"a"}, rr.PermittedRoles)
	})

}

func TestRule_toSerializableMap(t *testing.T) {
	_, internalNetwork, _ := net.ParseCIDR("192.168.0.0/16")
	protocol := "https"
	host := "example.com"
	requestURI := "/foo"
	timeout := 5 * time.Second

	t.Run("completely defined rule", func(t *testing.T) {
		r := &Rule{
			Name:            "test rule",
			SourceAddress:   internalNetwork,
			ProtocolPattern: &protocol,
			HostPattern:     &host,
			PathPattern:     &requestURI,
			Public:          false,
			PermittedRoles:  []string{"a", "b"},
			Timeout:         &timeout,
		}

		rr := r.toSerializableMap()

		assert.Equal(t, "test rule", rr["name"])
		assert.Equal(t, "192.168.0.0/16", rr["source_address"])
		assert.Equal(t, "https", rr["protocol_pattern"])
		assert.Equal(t, "example.com", rr["host_pattern"])
		assert.Equal(t, "/foo", rr["path_pattern"])
		assert.Equal(t, 5*time.Second, rr["timeout"])
	})

	t.Run("some things left undefined", func(t *testing.T) {
		r := &Rule{
			Name:           "a second rule",
			HostPattern:    &host,
			Public:         false,
			PermittedRoles: []string{"a"},
		}

		rr := r.toSerializableMap()

		assert.Equal(t, "a second rule", rr["name"])
		assert.Nil(t, rr["source_address"])
		assert.Nil(t, rr["protocol_pattern"])
		assert.Equal(t, "example.com", rr["host_pattern"])
		assert.Nil(t, rr["path_pattern"])
		assert.Nil(t, rr["timeout"])
	})
}
