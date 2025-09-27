package util

import (
	"encoding/base64"
	"net"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

var (
	Base64Encoder = base64.URLEncoding.WithPadding(base64.NoPadding)
)

func P[T any](x T) *T {
	return &x
}

func FindTrueIP(r *http.Request) string {
	if xrip := r.Header.Get("X-Real-Ip"); xrip != "" {
		return xrip
	}

	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		s := strings.Index(fwd, ", ")
		if s == -1 {
			s = len(fwd)
		}
		return fwd[:s]
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Warn().Str("remote_addr", r.RemoteAddr).Err(err).Msg("could find remote address")
	}

	return host
}
