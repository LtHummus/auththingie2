package redirects

type Validator interface {
	IsAllowed(rawURL string) bool
	Sanitize(rawURL string) (string, bool)
}
