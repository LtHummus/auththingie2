package rules

import (
	"net/url"
	"path"
	"strings"
)

func NormalizeURI(rawURI string) string {
	p, query, hasQuery := strings.Cut(rawURI, "?")

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

	if hasQuery {
		return p + "?" + query
	}

	return p
}

func NormalizeHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(h, "."))
}
