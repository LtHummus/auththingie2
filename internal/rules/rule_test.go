package rules

import (
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

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
		assert.Equal(t, "5s", rr["timeout"])
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

func fieldOrderSet() map[string]struct{} {
	m := make(map[string]struct{})
	for _, curr := range ruleFieldOrder {
		m[curr] = struct{}{}
	}

	return m
}

func TestSerializationFieldsAccountedFor(t *testing.T) {
	fields := fieldOrderSet()

	rt := reflect.TypeFor[rawRule]()
	for i := range rt.NumField() {
		field := rt.Field(i)

		tag := field.Tag.Get("mapstructure")
		if !assert.NotEmptyf(t, tag, "field %s has no mapstructure tag", field.Name) {
			continue
		}

		key, _, _ := strings.Cut(tag, ",") // omit ... uh ... ,omitempty
		if !assert.NotEmptyf(t, key, "field %s has empty mapstructure key", field.Name) {
			continue
		}

		_, fieldExists := fields[key]
		assert.Truef(t, fieldExists, "rawRule field %s (key %q) is missing from ruleFieldOrder", field.Name, key)
	}
}
