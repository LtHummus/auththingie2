package rules

import (
	"net/url"
	"path"
	"strings"
)

// NormalizeURI cleans up the URI by collapsing any sort of sneaky path escapes and also splits out the raw path
// from the query string and each are returned separately
func NormalizeURI(rawURI string) (string, string) {
	p, query, _ := strings.Cut(rawURI, "?")

	// if the normalization is malformed, just ignore it...won't match rules anyway
	if dec, err := url.PathUnescape(p); err == nil {
		p = dec
	}

	// path.Clean will strip trailing slashes, but we want to preserve them
	hasEndingSlash := strings.HasSuffix(p, "/")

	p = path.Clean(p)
	if p == "." || !strings.HasPrefix(p, "/") {
		p = "/" + strings.TrimPrefix(p, ".")
	}
	if hasEndingSlash && p != "/" {
		p += "/"
	}

	return p, query
}

func NormalizeHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(h, "."))
}
