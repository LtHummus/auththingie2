package util

import (
	"encoding/base64"
	"net/http"
	"strings"
)

var (
	Base64Encoder = base64.URLEncoding.WithPadding(base64.NoPadding)
	XRealIP       = http.CanonicalHeaderKey("X-Real-Ip")
	XForwardedFor = http.CanonicalHeaderKey("X-Forwarded-For")
)

func P[T any](x T) *T {
	return &x
}

func FindTrueIP(r *http.Request) string {
	switch {
	case r.Header.Get(XForwardedFor) != "":
		fwd := r.Header.Get(XForwardedFor)
		s := strings.Index(fwd, ", ")
		if s == -1 {
			s = len(fwd)
		}
		return fwd[:s]
	case r.Header.Get(XRealIP) != "":
		return r.Header.Get(XRealIP)
	default:
		return strings.Split(r.RemoteAddr, ":")[0]
	}
}
