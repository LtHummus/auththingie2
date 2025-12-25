package trueip

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

const (
	trustedProxyHeadersConfigKey = "security.trusted_proxies.network"
	updateDebounceTime           = 100 * time.Millisecond
)

type viperProvider struct {
	updateLock     sync.RWMutex
	lastUpdateTime time.Time

	trustedProxyIPs   []net.IP
	trustedProxyCIDRs []*net.IPNet
}

func (vp *viperProvider) updateTrustedProxies() {
	vp.updateLock.Lock()
	defer vp.updateLock.Unlock()

	if time.Since(vp.lastUpdateTime) < updateDebounceTime {
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
		if ip == nil {
			log.Warn().Str("input", curr).Msg("could not parse trusted proxy as CIDR or IP")
			continue
		}
		log.Debug().IPAddr("ip", ip).Msg("adding IP as trusted proxy")
		newTrustedIPs = append(newTrustedIPs, ip)
	}

	log.Info().Int("trusted_ip_count", len(newTrustedIPs)).Int("trusted_cidr_count", len(newTrustedCIDRs)).Msg("loaded trusted proxies")
	vp.trustedProxyIPs = newTrustedIPs
	vp.trustedProxyCIDRs = newTrustedCIDRs
	vp.lastUpdateTime = time.Now()
}

func (vp *viperProvider) ContainsProxies() bool {
	vp.updateLock.RLock()
	defer vp.updateLock.RUnlock()

	return len(vp.trustedProxyCIDRs) > 0 || len(vp.trustedProxyIPs) > 0
}

func (vp *viperProvider) Active() bool {
	return vp.ContainsProxies()
}

func (vp *viperProvider) GetTrustedProxies() []TrustedProxy {
	vp.updateLock.RLock()
	defer vp.updateLock.RUnlock()

	var ret []TrustedProxy
	for _, curr := range vp.trustedProxyIPs {
		ret = append(ret, TrustedProxy{
			Source:      "Config File - IP",
			Description: curr.String(),
		})
	}

	for _, curr := range vp.trustedProxyCIDRs {
		ret = append(ret, TrustedProxy{
			Source:      "Config File - CIDR",
			Description: curr.String(),
		})
	}

	return ret
}

func (vp *viperProvider) IsProxyTrusted(ip net.IP) bool {
	vp.updateLock.RLock()
	defer vp.updateLock.RUnlock()

	for _, curr := range vp.trustedProxyIPs {
		if curr.Equal(ip) {
			return true
		}
	}

	for _, curr := range vp.trustedProxyCIDRs {
		if curr.Contains(ip) {
			return true
		}
	}

	return false
}

func (vp *viperProvider) Teardown(ctx context.Context) error {
	// nop
	return nil
}

func newViperProvider() *viperProvider {
	vp := &viperProvider{}
	vp.updateTrustedProxies()
	return vp
}
