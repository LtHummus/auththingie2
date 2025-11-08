package rules

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/lthummus/auththingie2/internal/util"
)

func TestRawRule_ToRule(t *testing.T) {
	t.Run("all fields present", func(t *testing.T) {
		rr := rawRule{
			Name:            "test",
			SourceAddress:   util.P("10.0.0.0/8"),
			ProtocolPattern: util.P("https"),
			HostPattern:     util.P("foo.example.com"),
			PathPattern:     util.P("/index.html"),
			Public:          false,
			PermittedRoles:  []string{"a", "b"},
		}

		r, err := rr.ToRule()
		assert.NoError(t, err)

		assert.Equal(t, "test", r.Name)
		assert.True(t, net.ParseIP("10.0.0.0").Equal(r.SourceAddress.IP))
		assert.Equal(t, "ff000000", r.SourceAddress.Mask.String())
		assert.Equal(t, "https", *r.ProtocolPattern)
		assert.Equal(t, "foo.example.com", *r.HostPattern)
		assert.Equal(t, "/index.html", *r.PathPattern)
		assert.Equal(t, false, r.Public)
		assert.ElementsMatch(t, []string{"a", "b"}, r.PermittedRoles)
	})

	t.Run("fail on no name", func(t *testing.T) {
		rr := rawRule{}

		r, err := rr.ToRule()
		assert.Error(t, err)
		assert.Nil(t, r)
		assert.Equal(t, "rules: matcher: no name set", err.Error())
	})

	t.Run("fail on bad source address", func(t *testing.T) {
		rr := rawRule{
			Name:          "test",
			SourceAddress: util.P("abcd/efg"),
		}

		r, err := rr.ToRule()
		assert.Error(t, err)
		assert.Nil(t, r)

		// make sure the underlying error is a parse error from the `net` package
		wrappedError := errors.Unwrap(err)
		assert.NotNil(t, wrappedError)
		assert.IsType(t, &net.ParseError{}, wrappedError)
	})

	t.Run("leave fields blank if not defined", func(t *testing.T) {
		rr := rawRule{
			Name: "foo",
		}

		r, err := rr.ToRule()
		assert.NoError(t, err)

		assert.Equal(t, "foo", r.Name)
		assert.Nil(t, r.SourceAddress)
		assert.Nil(t, r.ProtocolPattern)
		assert.Nil(t, r.HostPattern)
		assert.Nil(t, r.PathPattern)
		assert.Nil(t, r.PermittedRoles)
		assert.False(t, r.Public)
	})
}
