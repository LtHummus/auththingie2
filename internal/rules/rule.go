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
