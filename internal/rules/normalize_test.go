package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		Input          string
		ExpectedOutput string
	}{
		{
			Input:          "foo.example.com",
			ExpectedOutput: "foo.example.com",
		},
		{
			Input:          "FOO.example.com",
			ExpectedOutput: "foo.example.com",
		},
		{
			Input:          "foo.EXAmPLE.com.",
			ExpectedOutput: "foo.example.com",
		},
	}

	for _, curr := range tests {
		t.Run(fmt.Sprintf("normalize %s", curr.Input), func(t *testing.T) {
			assert.Equal(t, curr.ExpectedOutput, NormalizeHost(curr.Input))
		})
	}
}

func TestNormalizeURI(t *testing.T) {
	tests := []struct {
		Name           string
		Input          string
		ExpectedOutput string
	}{
		{
			Name:           "basic test case (no query string)",
			Input:          "/admin/foo/bar",
			ExpectedOutput: "/admin/foo/bar",
		},
		{
			Name:           "basic test case (trailing slash)",
			Input:          "/admin/foo/bar/",
			ExpectedOutput: "/admin/foo/bar/",
		},
		{
			Name:           "basic test (with query string)",
			Input:          "/admin/foo/bar?hello=world&something=another_thing",
			ExpectedOutput: "/admin/foo/bar?hello=world&something=another_thing",
		},
		{
			Name:           "percent escape sequences",
			Input:          "/%61dmin/foo",
			ExpectedOutput: "/admin/foo",
		},
		{
			Name:           "percent escape sequences (a slash)",
			Input:          "/admin%2ffoo",
			ExpectedOutput: "/admin/foo",
		},
		{
			Name:           "percent escape sequence (trailing slash)",
			Input:          "/admin/foo%2f",
			ExpectedOutput: "/admin/foo/",
		},
		{
			Name:           "percent escape sequence with query (should not be escaped)",
			Input:          "/%61dmin/foo?bar=ba%39",
			ExpectedOutput: "/admin/foo?bar=ba%39",
		},
		{
			Name:           "path collapse",
			Input:          "//admin//foo",
			ExpectedOutput: "/admin/foo",
		},
		{
			Name:           "path collapse 2",
			Input:          "/admin/../../../bar",
			ExpectedOutput: "/bar",
		},
	}

	for _, curr := range tests {
		t.Run(curr.Name, func(t *testing.T) {
			assert.Equal(t, curr.ExpectedOutput, NormalizeURI(curr.Input))
		})
	}
}
