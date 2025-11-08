package ftue

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func mustMakeURL(source string) *url.URL {
	u, err := url.Parse(source)
	if err != nil {
		panic(err)
	}

	return u
}

func TestGetRootDomain(t *testing.T) {
	assert.Equal(t, "example.com", GetRootDomain(mustMakeURL("https://example.com")))
	assert.Equal(t, "example.com", GetRootDomain(mustMakeURL("https://test.example.com")))
	assert.Equal(t, "example.com", GetRootDomain(mustMakeURL("https://test.example.com/index.html")))
	assert.Equal(t, "example.biz", GetRootDomain(mustMakeURL("https://test.example.biz")))
	assert.Equal(t, "example.quix", GetRootDomain(mustMakeURL("https://foo.bar.example.quix")))
	assert.Equal(t, "bar.example:9000", GetRootDomain(mustMakeURL("https://foo.bar.example:9000")))
	assert.Equal(t, "localhost:9000", GetRootDomain(mustMakeURL("http://localhost:9000")))
}
