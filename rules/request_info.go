package rules

import (
	"net"
	"net/url"
)

type RequestInfo struct {
	Method     string
	Protocol   string
	Host       string
	RequestURI string
	SourceIP   net.IP
}

func (ri *RequestInfo) Valid() bool {
	return ri.Method != "" && ri.Protocol != "" && ri.Host != "" && ri.RequestURI != "" && ri.SourceIP != nil
}

func (ri *RequestInfo) GetURL() string {
	dest := url.URL{
		Scheme: ri.Protocol,
		Host:   ri.Host,
		Path:   ri.RequestURI,
	}
	return dest.String()
}
