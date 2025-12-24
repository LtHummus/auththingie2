package trueip

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/notices"
)

const (
	trustedIpHeaderConfigKey = "security.real_ip_header"
)

type TrustedProxy struct {
	Source      string
	Description string
}

type trustedProxyProvider interface {
	IsProxyTrusted(ip net.IP) bool
	ContainsProxies() bool
	GetTrustedProxies() []TrustedProxy
	Active() bool
}

var trustedProxyProviders []trustedProxyProvider

func Initialize(ctx context.Context) {
	if dp := newDockerProvider(ctx); dp != nil {
		trustedProxyProviders = append(trustedProxyProviders, dp)
	}

	if vp := newViperProvider(); vp != nil {
		trustedProxyProviders = append(trustedProxyProviders, vp)
	}

	initOK := false

	for _, curr := range trustedProxyProviders {
		if curr.Active() {
			initOK = true
			break
		}
	}

	if !initOK {
		notices.AddMessage("no-proxies-trusted", "There are no proxies trusted! This means that source IP detection is insecure!")
	}
}

func isTrustedProxy(r *http.Request) bool {
	remoteIPStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Warn().Str("remote_addr", r.RemoteAddr).Err(err).Msg("could find remote address for testing trusted proxy")
		return false
	}

	remoteIP := net.ParseIP(remoteIPStr)
	if remoteIP == nil {
		log.Warn().Str("remote_ip", remoteIPStr).Msg("could not parse remote as IP")
		return false
	}

	for _, curr := range trustedProxyProviders {
		if curr.IsProxyTrusted(remoteIP) {
			return true
		}
	}

	log.Warn().IPAddr("remote_ip", remoteIP).Msg("not trusting XFF header from unknown proxy")
	return false
}

// safeGetXForwardedFor safely gets the XFF header contents (or emptystring if no such header exists). We do things this
// way because we can only trust the LAST instance of XFF and `Header.Get("X-Forwarded-For")` will return the first instance
func safeGetXForwardedFor(r *http.Request) string {
	headers := r.Header.Values("X-Forwarded-For")
	if len(headers) == 0 {
		return ""
	}
	return headers[len(headers)-1]
}

func ListProxies() []TrustedProxy {
	var ret []TrustedProxy

	for _, curr := range trustedProxyProviders {
		ret = append(ret, curr.GetTrustedProxies()...)
	}

	return ret
}

func Find(r *http.Request) string {
	if trustedHeaderName := viper.GetString(trustedIpHeaderConfigKey); trustedHeaderName != "" {
		upstreamTrusted := isTrustedProxy(r)
		if trustedContents := r.Header.Get(trustedHeaderName); upstreamTrusted && trustedContents != "" {
			return trustedContents
		}

		log.Warn().Str("trusted_header_name", trustedHeaderName).Msg("security.trusted_header_name is set, but that header isn't in the request")
	}

	if fwd := safeGetXForwardedFor(r); fwd != "" {
		if isTrustedProxy(r) {
			s := strings.Index(fwd, ",")
			if s == -1 {
				s = len(fwd)
			}
			return strings.TrimSpace(fwd[:s])
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Warn().Str("remote_addr", r.RemoteAddr).Err(err).Msg("could find remote address")
	}

	return host
}
