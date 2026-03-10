package maxbytes

import "net/http"

type Middleware struct {
	handler http.Handler

	maxBytes int64
}

func NewMaxBytesMiddleware(next http.Handler, maxBytes int64) *Middleware {
	return &Middleware{
		handler:  next,
		maxBytes: maxBytes,
	}
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, m.maxBytes)
	m.handler.ServeHTTP(w, r)
}
