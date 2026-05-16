package redirects

type Validator interface {
	IsAllowed(rawURL string) bool

	// Sanitize takes a rawURL and returns a redirect URL that is usable. If the URL is allowed, it returns the same
	// URL. If the URL is not allowed, it returns some sort of fallback url. The boolean returned indicates if the URL
	// is a fallback URL or not (i.e. if the URL was replaced)
	Sanitize(rawURL string) (string, bool)
}
