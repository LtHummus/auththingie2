package util

// go1.26 can't come soon enough and I can delete this https://go.googlesource.com/go/+/refs/heads/master/doc/next/2-language.md

func P[T any](x T) *T {
	return &x
}
