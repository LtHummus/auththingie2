package trueip

import (
	"net"
	"net/http"
	"net/textproto"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

type testProvider struct {
	validIP net.IP
}

func (tp *testProvider) IsProxyTrusted(ip net.IP) bool {
	return ip.Equal(tp.validIP)
}
func (tp *testProvider) ContainsProxies() bool { return tp.validIP != nil }
func (tp *testProvider) Active() bool          { return tp.ContainsProxies() }
func (tp *testProvider) GetTrustedProxies() []TrustedProxy {
	if tp.validIP != nil {
		return []TrustedProxy{
			{
				Source:      "Test Provider",
				Description: tp.validIP.String(),
			},
		}
	}

	return nil

}

func trustIPForProxy(t *testing.T, ip string) {
	t.Cleanup(func() {
		trustedProxyProviders = nil
	})

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		t.Fatalf("could not parse IP to trust: %s", ip)
	}

	trustedProxyProviders = []trustedProxyProvider{
		&testProvider{validIP: parsedIP},
	}
}

func TestFind(t *testing.T) {
	t.Run("fallback", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "1.2.3.4:59884",
		}

		assert.Equal(t, "1.2.3.4", Find(r))
	})

	t.Run("trust XFF if proxy is trusted", func(t *testing.T) {
		trustIPForProxy(t, "1.2.3.4")
		r := &http.Request{
			RemoteAddr: "1.2.3.4:5892",
			Header:     map[string][]string{},
		}

		r.Header.Set("X-Forwarded-For", "9.9.9.9")

		assert.Equal(t, "9.9.9.9", Find(r))
	})

	t.Run("do not trust XFF is proxy is untrusted", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "1.2.3.4:5892",
			Header:     map[string][]string{},
		}

		r.Header.Set("X-Forwarded-For", "9.9.9.9")

		assert.Equal(t, "1.2.3.4", Find(r))
	})

	t.Run("always take last XFF header", func(t *testing.T) {
		trustIPForProxy(t, "127.0.0.1")
		r := &http.Request{
			RemoteAddr: "127.0.0.1:5999",
			Header: map[string][]string{
				textproto.CanonicalMIMEHeaderKey("X-Forwarded-For"): {
					"1.1.1.1",
					"2.2.2.2",
				},
			},
		}

		assert.Equal(t, "2.2.2.2", Find(r))
	})

	t.Run("take rightmost entry in XFF", func(t *testing.T) {
		trustIPForProxy(t, "127.0.0.1")
		r := &http.Request{
			RemoteAddr: "127.0.0.1:5999",
			Header:     map[string][]string{},
		}
		r.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2")

		assert.Equal(t, "2.2.2.2", Find(r))
	})

	t.Run("use custom trust header if configured and present and proxy is trusted", func(t *testing.T) {
		trustIPForProxy(t, "127.0.0.1")
		t.Cleanup(func() {
			viper.Reset()
		})
		r := &http.Request{
			RemoteAddr: "127.0.0.1:5999",
			Header:     map[string][]string{},
		}
		r.Header.Set("X-Real-IP", "1.1.1.1")

		viper.Set(trustedIpHeaderConfigKey, "x-real-ip")

		assert.Equal(t, "1.1.1.1", Find(r))
	})

	t.Run("ignore set trust header if not coming from proxy", func(t *testing.T) {
		trustIPForProxy(t, "127.0.0.1")
		t.Cleanup(func() {
			viper.Reset()
		})
		r := &http.Request{
			RemoteAddr: "127.0.0.5:5999",
			Header:     map[string][]string{},
		}
		r.Header.Set("X-Real-IP", "1.1.1.1")

		viper.Set(trustedIpHeaderConfigKey, "x-real-ip")

		assert.Equal(t, "127.0.0.5", Find(r))
	})
}

func Test_isTrustedProxy(t *testing.T) {
	t.Run("no trust if you can't parse remote addr", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "aaaaaaa",
		}

		assert.False(t, isTrustedProxy(r))
	})

	t.Run("no trust if you can't parse a source IP", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "992.281.495.111:9999",
		}

		assert.False(t, isTrustedProxy(r))
	})
}
