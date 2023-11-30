package rules

import (
	"net"
	"time"

	"github.com/spf13/viper"
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

func nonDefaultString(x string) *string {
	if x != "" {
		return &x
	}
	return nil
}

func New(v *viper.Viper) (*Rule, error) {
	name := v.GetString("name")
	source := v.GetString("source")
	protocol := v.GetString("protocol_pattern")
	host := v.GetString("host_pattern")
	path := v.GetString("path_pattern")
	timeout := v.GetDuration("timeout")
	public := v.GetBool("public")
	permittedRoles := v.GetStringSlice("roles")

	var addr *net.IPNet
	if source != "" {
		_, n, err := net.ParseCIDR(source)
		if err != nil {
			return nil, err
		}
		addr = n
	}

	trueTimeout := &timeout
	if timeout == 0 {
		trueTimeout = nil
	}

	return &Rule{
		Name:            name,
		SourceAddress:   addr,
		ProtocolPattern: nonDefaultString(protocol),
		HostPattern:     nonDefaultString(host),
		PathPattern:     nonDefaultString(path),
		Timeout:         trueTimeout,
		Public:          public,
		PermittedRoles:  permittedRoles,
	}, nil
}

func internalMatch(pattern string, candidate string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '?':
			// make sure we have at least one character we can consume
			if len(candidate) == 0 {
				return false
			}
		case '*':
			return internalMatch(pattern[1:], candidate) || (len(candidate) > 0 && internalMatch(pattern, candidate[1:]))
		default:
			if len(candidate) == 0 || candidate[0] != pattern[0] {
				return false
			}
		}

		candidate = candidate[1:]
		pattern = pattern[1:]
	}

	return len(candidate) == 0 && len(pattern) == 0
}

func (r *Rule) Matches(ri *RequestInfo) bool {
	// OPTIMIZE: we can return early if a match does not happen for a given rule

	sourceMatch := r.SourceAddress == nil || r.SourceAddress.Contains(ri.SourceIP)
	protocolMatch := r.ProtocolPattern == nil || internalMatch(*r.ProtocolPattern, ri.Protocol)
	hostMatch := r.HostPattern == nil || internalMatch(*r.HostPattern, ri.Host)
	pathMatch := r.PathPattern == nil || internalMatch(*r.PathPattern, ri.RequestURI)

	return sourceMatch && protocolMatch && hostMatch && pathMatch
}

func (r *Rule) toRawRule() rawRule {
	rr := rawRule{}
	rr.Name = r.Name
	if r.SourceAddress != nil {
		srcAddrString := r.SourceAddress.String()
		rr.SourceAddress = &srcAddrString
	}

	rr.ProtocolPattern = r.ProtocolPattern
	rr.HostPattern = r.HostPattern
	rr.PathPattern = r.PathPattern

	rr.Public = r.Public
	rr.PermittedRoles = r.PermittedRoles

	return rr
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
		m["timeout"] = *r.Timeout
	}

	return m
}
