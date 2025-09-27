package trueip

import (
	"net"
	"net/http"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestFindTrueIP(t *testing.T) {
	t.Run("fallback", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "1.2.3.4:5984",
		}

		assert.Equal(t, "1.2.3.4", Find(r))
	})

	t.Run("x-forwarded-for w/ empty trusted settings", func(t *testing.T) {
		trustedProxyIPs = nil
		trustedProxyCIDRs = nil
		r := &http.Request{
			RemoteAddr: "1.2.3.4:5892",
			Header:     map[string][]string{},
		}
		r.Header.Set("X-Forwarded-For", "192.168.2.1")

		assert.Equal(t, "192.168.2.1", Find(r))
	})

	t.Run("x-forwarded-for (multiple) w/ empty trusted settings", func(t *testing.T) {
		trustedProxyIPs = nil
		trustedProxyCIDRs = nil
		r := &http.Request{
			RemoteAddr: "1.2.3.4:5892",
			Header:     map[string][]string{},
		}
		r.Header.Set("X-Forwarded-For", "192.168.2.1, 999.999.999.999")

		assert.Equal(t, "192.168.2.1", Find(r))
	})

	t.Run("do not trust XFF if proxy is untrusted", func(t *testing.T) {
		trustedProxyIPs = []net.IP{net.ParseIP("127.0.0.1")}
		r := &http.Request{
			RemoteAddr: "1.2.3.4:5892",
			Header:     map[string][]string{},
		}
		r.Header.Set("X-Forwarded-For", "192.168.2.1")

		assert.Equal(t, "1.2.3.4", Find(r))
	})

	t.Run("trust XFF if proxy IP is trusted", func(t *testing.T) {
		trustedProxyCIDRs = nil
		trustedProxyIPs = []net.IP{net.ParseIP("127.0.0.1")}
		r := &http.Request{
			RemoteAddr: "127.0.0.1:5892",
			Header:     map[string][]string{},
		}
		r.Header.Set("X-Forwarded-For", "192.168.2.1")

		assert.Equal(t, "192.168.2.1", Find(r))
	})

	t.Run("trust XFF is proxy CIDR is trusted", func(t *testing.T) {
		_, ipn, _ := net.ParseCIDR("10.0.0.0/8")
		trustedProxyIPs = nil
		trustedProxyCIDRs = []*net.IPNet{ipn}
		r := &http.Request{
			RemoteAddr: "10.20.30.40:3945",
			Header:     map[string][]string{},
		}
		r.Header.Set("X-Forwarded-For", "192.168.2.1")

		assert.Equal(t, "192.168.2.1", Find(r))
	})

	t.Run("ignore x-real-ip if not enabled", func(t *testing.T) {
		t.Cleanup(func() {
			viper.Reset()
		})
		r := &http.Request{
			RemoteAddr: "1.2.3.4:5892",
			Header:     map[string][]string{},
		}
		r.Header.Set("X-Real-Ip", "192.195.199.199")

		assert.Equal(t, "1.2.3.4", Find(r))
	})

	t.Run("x-real-ip only trusted if enabled", func(t *testing.T) {
		viper.Set(trustedIpHeaderConfigKey, "x-real-ip")
		t.Cleanup(func() {
			viper.Reset()
		})
		r := &http.Request{
			RemoteAddr: "1.2.3.4:5892",
			Header:     map[string][]string{},
		}
		r.Header.Set("X-Real-Ip", "192.195.199.199")

		assert.Equal(t, "192.195.199.199", Find(r))
	})

	t.Run("fallback order", func(t *testing.T) {
		viper.Set(trustedIpHeaderConfigKey, "x-real-ip")
		t.Cleanup(func() {
			viper.Reset()
		})
		r := &http.Request{
			RemoteAddr: "1.2.3.4:5892",
			Header:     map[string][]string{},
		}
		r.Header.Set("X-Real-Ip", "192.195.199.199")
		r.Header.Set("X-Forwarded-For", "192.168.2.1, 999.999.999.999")

		assert.Equal(t, "192.195.199.199", Find(r))
	})
}
