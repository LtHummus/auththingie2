package rules

import (
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestInfo_Valid(t *testing.T) {
	ri := &RequestInfo{}

	assert.False(t, ri.Valid())

	ri.Method = "GET"
	assert.False(t, ri.Valid())

	ri.Protocol = "https"
	assert.False(t, ri.Valid())

	ri.Host = "foo.example.com"
	assert.False(t, ri.Valid())

	ri.RequestURI = "/index.html"
	assert.False(t, ri.Valid())

	ri.SourceIP = net.ParseIP("10.0.0.1")
	assert.True(t, ri.Valid())
}

func TestRequestInfo_GetURL(t *testing.T) {
	ri := &RequestInfo{
		Method:     http.MethodGet,
		Protocol:   "https",
		Host:       "example.com",
		RequestURI: "/foo",
		SourceIP:   net.ParseIP("127.0.0.1"),
	}

	assert.Equal(t, "https://example.com/foo", ri.GetURL())
}
