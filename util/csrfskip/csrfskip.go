package csrfskip

import (
	"net/http"
	"strings"

	"github.com/gorilla/csrf"
)

type Skipper struct {
	exemptPaths map[string]bool
	h           http.Handler
}

func NewSkipper(exemptPaths []string) func(h http.Handler) http.Handler {
	exemptMap := make(map[string]bool)
	for _, curr := range exemptPaths {
		exemptMap[curr] = true
	}
	return func(h http.Handler) http.Handler {
		return &Skipper{
			h:           h,
			exemptPaths: exemptMap,
		}
	}

}

func (s *Skipper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/static/") || s.exemptPaths[r.URL.Path] {
		r = csrf.UnsafeSkipCheck(r)
	}
	s.h.ServeHTTP(w, r)
}
