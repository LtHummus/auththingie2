package trueip

import (
	"context"
	"fmt"
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
	Teardown(ctx context.Context) error
}

var (
	trustedProxyProviders []trustedProxyProvider
	providerLock          sync.RWMutex
)

func Initialize(ctx context.Context) error {
	err := initFromConfig(ctx)
	if err != nil {
		return fmt.Errorf("trueip: Intialize: no trusted proxy configuration. Please configure this. See README for details")
	}

	config.RegisterForUpdates(func(event fsnotify.Event) {
		log.Debug().Msg("reloading trusted proxy config")
		err = initFromConfig(context.Background())
		log.Warn().Err(err).Msg("invalid proxy configuration")
	})

	return nil
}

func initFromConfig(ctx context.Context) error {
	providerLock.Lock()
	defer providerLock.Unlock()

	for _, curr := range trustedProxyProviders {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		err := curr.Teardown(ctx)
		if err != nil {
			log.Error().Err(err).Msg("could not tear down trusted proxy provider")
		}
		cancel()
	}

	var newTrustedProviders []trustedProxyProvider
	if dp := newDockerProvider(ctx); dp != nil {
		newTrustedProviders = append(newTrustedProviders, dp)
	}

	if vp := newViperProvider(); vp != nil {
		newTrustedProviders = append(newTrustedProviders, vp)
	}

	initOK := false

	for _, curr := range newTrustedProviders {
		if curr.Active() {
			initOK = true
			break
		}
	}

	if !initOK {
		notices.AddMessage("no-proxies-trusted", "There are no proxies trusted! This means that source IP detection is insecure!")
	} else {
		notices.DeleteMessage("no-proxies-trusted")
	}

	trustedProxyProviders = newTrustedProviders

	if !initOK {
		return fmt.Errorf("trueip: initFromConfig: no trusted proxy providers configured")
	}

	return nil
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
	providerLock.RLock()
	defer providerLock.RUnlock()

	var ret []TrustedProxy

	for _, curr := range trustedProxyProviders {
		ret = append(ret, curr.GetTrustedProxies()...)
	}

	return ret
}

func Find(r *http.Request) string {
	providerLock.RLock()
	defer providerLock.RUnlock()
	upstreamTrusted := isTrustedProxy(r)
	if trustedHeaderName := viper.GetString(trustedIpHeaderConfigKey); upstreamTrusted && trustedHeaderName != "" {
		if trustedContents := r.Header.Get(trustedHeaderName); trustedContents != "" {
			return trustedContents
		}

		log.Warn().Str("trusted_header_name", trustedHeaderName).Msg("security.trusted_header_name is set, but that header isn't in the request")
		notices.AddMessage("invalid-trusted-header-name", "security.trusted_header_name has been set, but we haven't been seeing it in requests")
	} else if fwd := safeGetXForwardedFor(r); upstreamTrusted && fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Warn().Str("remote_addr", r.RemoteAddr).Err(err).Msg("could find remote address")
	}

	return host
}
