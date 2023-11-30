package rules

import (
	"errors"
	"fmt"
	"net"
	"time"
)

type rawRule struct {
	Name            string         `mapstructure:"name"`
	SourceAddress   *string        `mapstructure:"source_address,omitempty"`
	ProtocolPattern *string        `mapstructure:"protocol_pattern,omitempty"`
	HostPattern     *string        `mapstructure:"host_pattern,omitempty"`
	PathPattern     *string        `mapstructure:"path_pattern,omitempty"`
	Timeout         *time.Duration `mapstructure:"timeout,omitempty"`
	Public          bool           `mapstructure:"public"`
	PermittedRoles  []string       `mapstructure:"permitted_roles"`
}

func (rr *rawRule) ToRule() (*Rule, error) {
	ret := Rule{}

	if rr.Name == "" {
		return nil, errors.New("rules: matcher: no name set")
	}
	ret.Name = rr.Name
	ret.Timeout = rr.Timeout

	if rr.SourceAddress != nil {
		_, n, err := net.ParseCIDR(*rr.SourceAddress)
		if err != nil {
			return nil, fmt.Errorf("rules: matcher: invalid CIDR: %w", err)
		}
		ret.SourceAddress = n
	}

	if rr.ProtocolPattern != nil {
		ret.ProtocolPattern = rr.ProtocolPattern
	}

	if rr.HostPattern != nil {
		ret.HostPattern = rr.HostPattern
	}

	if rr.PathPattern != nil {
		ret.PathPattern = rr.PathPattern
	}

	ret.Public = rr.Public
	ret.PermittedRoles = rr.PermittedRoles

	return &ret, nil
}
