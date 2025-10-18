package securityheaders

import "net/http"

type Middleware struct {
	handler http.Handler
}

func NewSecurityHeadersMiddleware(next http.Handler) *Middleware {
	return &Middleware{
		handler: next,
	}
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;")

	m.handler.ServeHTTP(w, r)
}
