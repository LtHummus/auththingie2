package rules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInternalMatch(t *testing.T) {
	groups := map[string][]struct {
		pattern   string
		candidate string
		matches   bool
	}{
		"easy cases": {
			{"abc", "abc", true},
			{"a", "a", true},
		},
		"trailing stars": {
			{"*", "abcdefg", true},
			{"a*", "abc", true},
			{"a*", "babc", false},
		},
		"question marks": {
			{"a?c", "abc", true},
			{"a??", "abc", true},
			{"a??", "ab", false},
		},
		"empty edges": {
			{"", "", true},
			{"*", "", true},
			{"", "abc", false},
			{"abc", "", false},
		},
		"length mismatches": {
			{"abc", "abcd", false},
			{"abcd", "abc", false},
		},
		"star matches zero characters": {
			{"a*", "a", true},
			{"*abc", "abc", true},
			{"a*b*c", "abc", true},
			{"***", "", true},
			{"a**b", "ab", true},
			{"a**", "a", true},
		},
		"? edge cases": {
			{"a?", "a", false},
			{"?", "", false},
			{"a?b", "a/b", true},
			{"?*", "", false},
		},
		"backtracking": {
			{"*abc", "abcabc", true},
			{"*.js", "script.js", true},
			{"*.js", "script.jsx", false},
		},
		"paths": {
			{"/api/*/users", "/api/v2/users", true},
			{"/api/*", "/api/v2/users", true},
			{"/static/*/*.js", "/static/vendor/js/script.js", true},
			{"/admin/*", "/public/index.html", false},
			{"/api/v1/*", "/api/v2/ping", false},
		},
		"long ones": {
			{strings.Repeat("?", 50), strings.Repeat("a", 50), true},
			{strings.Repeat("*", 50), strings.Repeat("a", 50), true},
			{strings.Repeat("*", 49), strings.Repeat("a", 50), true},
		},
		"adversarial backtracking": {
			{"*a*a*a*a*a*a*a*a*a*", strings.Repeat("a", 50), true},
			{"*a*a*a*a*a*a*a*a*a*b", strings.Repeat("a", 50), false},
			{strings.Repeat("*a", 30), strings.Repeat("a", 50), true},
		},
		"unicode stuff": {
			{"*", "🍔", true},
			{"hamburger?", "hamburger🍔", true},
			{"caf?", "café", true},
			{"caf??", "café", false},
			{"caf*", "café", true},
		},
	}

	for name, cases := range groups {
		t.Run(name, func(t *testing.T) {
			for _, c := range cases {
				t.Run(fmt.Sprintf("%q vs %q", c.pattern, c.candidate), func(t *testing.T) {
					assert.Equal(t, c.matches, internalMatch(c.pattern, c.candidate))
					assert.Equal(t, c.matches, internalMatchUnicode(c.pattern, c.candidate)) // make sure the implementations don't drift
				})
			}
		})
	}
}

func BenchmarkInternalMatch(b *testing.B) {
	cases := []struct {
		Name      string
		Pattern   string
		Candidate string
	}{
		{"simple_path", "/api/*", "/api/v2/users"},
		{"star_in_middle", "/static/*/*.js", "/static/vendor/js/script.js"},
		{"no_match", "/admin/*", "/public/index.html"},
		{"adversarial", strings.Repeat("*a", 30), strings.Repeat("a", 50) + "b"},
		{"unicode", "caf*", "café"},
		{"long_candidate_string", "*", strings.Repeat("a", 512)},
		{"long_unicode", "*", strings.Repeat("á", 50)},
	}

	for _, curr := range cases {
		b.Run(curr.Name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				internalMatch(curr.Pattern, curr.Candidate)
			}
		})
	}
}
