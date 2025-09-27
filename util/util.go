package util

import (
	"encoding/base64"
)

var (
	Base64Encoder = base64.URLEncoding.WithPadding(base64.NoPadding)
)

func P[T any](x T) *T {
	return &x
}
