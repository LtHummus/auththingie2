package rules

import (
	"github.com/lthummus/auththingie2/durations"
)

type DisplayableRule struct {
	Name      string
	Source    string
	Protocol  string
	Host      string
	Path      string
	Roles     []string
	Timeout   string
	IsPublic  bool
	AdminOnly bool
}

func RuleToDisplayableRule(r Rule) *DisplayableRule {
	dr := &DisplayableRule{
		Name:      r.Name,
		Source:    "*",
		Protocol:  "*",
		Host:      "*",
		Path:      "*",
		Roles:     r.PermittedRoles,
		Timeout:   "",
		IsPublic:  r.Public,
		AdminOnly: !r.Public && len(r.PermittedRoles) == 0,
	}

	if r.SourceAddress != nil {
		dr.Source = r.SourceAddress.String()
	}

	if r.ProtocolPattern != nil {
		dr.Protocol = *r.ProtocolPattern
	}

	if r.HostPattern != nil {
		dr.Host = *r.HostPattern
	}

	if r.PathPattern != nil {
		dr.Path = *r.PathPattern
	}

	if r.Timeout != nil {
		dr.Timeout = durations.NiceDuration(*r.Timeout)
	}

	return dr
}
