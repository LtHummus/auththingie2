package trueip

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/config"
	"github.com/lthummus/auththingie2/internal/notices"
)

const (
	trustedProxyHeadersConfigKey = "security.trusted_proxies.network"
	trustedIpHeaderConfigKey     = "security.real_ip_header"
	updateDebounceTime           = 100 * time.Millisecond
)

var (
	updateLock     sync.RWMutex
	lastUpdateTime time.Time

	trustedProxyIPs   []net.IP
	trustedProxyCIDRs []*net.IPNet
)

func Initialize() {
	updateTrustedProxies()
	config.RegisterForUpdates(func(event fsnotify.Event) {
		updateTrustedProxies()
	})
}

func setNoTrustedProxyWarning() {
	notices.AddMessage("no-trusted-proxy", "security.trusted_proxies.network is not set. This will allow all X-Forwarded-For headers to be implicitly trusted! To remove this message, configure security.trusted_proxies.network to be the IP address or CIDR of your reverse proxy. I reserve the right to make this a fatal error in future versions")
	log.Warn().Msg("security.trusted_proxies.network is not set. This will allow all X-Forwarded-For headers to be implicitly trusted! Set security.trusted_proxies.network to be a list of trusted IPs/CIDRs to ignore this message")
}

func updateTrustedProxies() {
	updateLock.Lock()
	defer updateLock.Unlock()

	if time.Since(lastUpdateTime) < updateDebounceTime {
		return
	}

	var newTrustedIPs []net.IP
	var newTrustedCIDRs []*net.IPNet

	for _, curr := range viper.GetStringSlice(trustedProxyHeadersConfigKey) {
		_, ipnet, err := net.ParseCIDR(curr)
		// note opposite of normal error check!
		if err == nil {
			log.Debug().IPPrefix("cidr", *ipnet).Msg("adding CIDR as trusted proxy")
			newTrustedCIDRs = append(newTrustedCIDRs, ipnet)
			continue
		}

		ip := net.ParseIP(curr)
		if ip != nil {
			log.Warn().Str("input", curr).Msg("could not parse trusted proxy as CIDR or IP")
			continue
		}
		log.Debug().IPAddr("ip", ip).Msg("adding IP as trusted proxy")
		newTrustedIPs = append(newTrustedIPs, ip)
	}

	log.Info().Int("trusted_ip_count", len(newTrustedIPs)).Int("trusted_cidr_count", len(newTrustedCIDRs)).Msg("loaded trusted proxies")
	trustedProxyIPs = newTrustedIPs
	trustedProxyCIDRs = newTrustedCIDRs
	lastUpdateTime = time.Now()
	if len(trustedProxyCIDRs) == 0 && len(trustedProxyIPs) == 0 {
		setNoTrustedProxyWarning()
	}
}

func isTrustedProxy(r *http.Request) bool {
	updateLock.RLock()
	defer updateLock.RUnlock()

	if len(trustedProxyCIDRs) == 0 && len(trustedProxyIPs) == 0 {
		setNoTrustedProxyWarning()
		return true
	}

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

	for _, curr := range trustedProxyIPs {
		if curr.Equal(remoteIP) {
			return true
		}
	}

	for _, curr := range trustedProxyCIDRs {
		if curr.Contains(remoteIP) {
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

func Find(r *http.Request) string {
	if trustedHeaderName := viper.GetString(trustedIpHeaderConfigKey); trustedHeaderName != "" {
		if trustedContents := r.Header.Get(trustedHeaderName); trustedContents != "" {
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
