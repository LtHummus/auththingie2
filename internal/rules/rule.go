package rules

import (
	"net"
	"time"
)

type Rule struct {
	Name            string
	SourceAddress   *net.IPNet
	ProtocolPattern *string
	HostPattern     *string
	PathPattern     *string
	Timeout         *time.Duration
	Public          bool
	PermittedRoles  []string
}

// internalMatch matches input against patterns such as `/api/*`
// a * in a pattern matches many characters. A ? matches a single character. We can not use path.Match here because
// we want * to match across separators (e.g. `/api/*` would match `/api/foo` but not `/api/v1/foo). Note for future self
// using the library `doublestar` could work here, but would break configs since `*` won't match across separators, but
// ** will
func internalMatch(pattern string, candidate string) bool {
	p := 0
	c := 0

	lastStar := -1
	starMatches := 0

	for c < len(candidate) {
		if p < len(pattern) && pattern[p] == '*' {
			lastStar = p
			starMatches = c
			p++
		} else if p < len(pattern) && (pattern[p] == '?' || pattern[p] == candidate[c]) {
			// match single character (either literal or ?)
			p++
			c++
		} else if lastStar != -1 {
			starMatches++
			p = lastStar + 1
			c = starMatches
		} else {
			return false
		}
	}

	for p < len(pattern) && pattern[p] == '*' {
		p++
	}

	return p == len(pattern)
}

func (r *Rule) Matches(ri *RequestInfo) bool {
	// OPTIMIZE: we can return early if a match does not happen for a given rule

	sourceMatch := r.SourceAddress == nil || r.SourceAddress.Contains(ri.SourceIP)
	protocolMatch := r.ProtocolPattern == nil || internalMatch(*r.ProtocolPattern, ri.Protocol)
	hostMatch := r.HostPattern == nil || internalMatch(*r.HostPattern, ri.Host)
	pathMatch := r.PathPattern == nil || internalMatch(*r.PathPattern, ri.RequestURI)

	return sourceMatch && protocolMatch && hostMatch && pathMatch
}

func (r *Rule) toSerializableMap() map[string]interface{} {
	m := map[string]interface{}{
		"name":            r.Name,
		"public":          r.Public,
		"permitted_roles": r.PermittedRoles,
	}

	if r.SourceAddress != nil {
		m["source_address"] = r.SourceAddress.String()
	}

	if r.ProtocolPattern != nil {
		m["protocol_pattern"] = *r.ProtocolPattern
	}

	if r.HostPattern != nil {
		m["host_pattern"] = *r.HostPattern
	}

	if r.PathPattern != nil {
		m["path_pattern"] = *r.PathPattern
	}

	if r.Timeout != nil {
		m["timeout"] = (*r.Timeout).String()
	}

	return m
}
