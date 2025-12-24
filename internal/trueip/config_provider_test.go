package trueip

import (
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestViperProvider_IsProxyTrusted(t *testing.T) {
	t.Run("happy case, explicit IP", func(t *testing.T) {
		vp := &viperProvider{
			trustedProxyIPs: []net.IP{
				net.ParseIP("127.0.0.1"),
				net.ParseIP("1.1.2.2"),
			},
		}

		assert.True(t, vp.IsProxyTrusted(net.ParseIP("127.0.0.1")))
		assert.True(t, vp.IsProxyTrusted(net.ParseIP("1.1.2.2")))
		assert.False(t, vp.IsProxyTrusted(net.ParseIP("59.29.11.11")))
	})

	t.Run("happy case, explicit CIDR", func(t *testing.T) {
		_, cidr, err := net.ParseCIDR("172.16.0.0/12")
		require.NoError(t, err)
		vp := &viperProvider{
			trustedProxyCIDRs: []*net.IPNet{cidr},
		}

		assert.True(t, vp.IsProxyTrusted(net.ParseIP("172.16.11.11")))
		assert.True(t, vp.IsProxyTrusted(net.ParseIP("172.16.11.12")))
		assert.True(t, vp.IsProxyTrusted(net.ParseIP("172.16.99.12")))
		assert.True(t, vp.IsProxyTrusted(net.ParseIP("172.30.0.0")))
		assert.False(t, vp.IsProxyTrusted(net.ParseIP("172.50.0.0")))
	})
}

func TestViperProvider_updateTrustedProxies(t *testing.T) {
	t.Run("happy case", func(t *testing.T) {
		t.Cleanup(func() {
			viper.Reset()
		})

		viper.Set(trustedProxyHeadersConfigKey, []string{
			"127.0.0.1",
			"172.16.0.0/12",
			"blahblah", // this should be cleanly ignored
		})

		vp := &viperProvider{}
		vp.updateTrustedProxies()

		assert.Len(t, vp.trustedProxyIPs, 1)
		assert.Len(t, vp.trustedProxyCIDRs, 1)
		assert.WithinDuration(t, time.Now(), vp.lastUpdateTime, 1*time.Second)

		assert.True(t, vp.IsProxyTrusted(net.ParseIP("127.0.0.1")))
		assert.True(t, vp.IsProxyTrusted(net.ParseIP("172.16.11.0")))
		assert.False(t, vp.IsProxyTrusted(net.ParseIP("192.168.2.1")))
	})

	t.Run("ignore updates if they happen too quickly", func(t *testing.T) {
		t.Cleanup(func() {
			viper.Reset()
		})

		synctest.Test(t, func(t *testing.T) {
			viper.Set(trustedProxyHeadersConfigKey, []string{
				"127.0.0.1",
				"172.16.0.0/12",
			})

			vp := &viperProvider{}
			vp.updateTrustedProxies()

			assert.True(t, vp.IsProxyTrusted(net.ParseIP("127.0.0.1")))
			assert.True(t, vp.IsProxyTrusted(net.ParseIP("172.20.0.0")))

			time.Sleep(updateDebounceTime / 2)

			viper.Set(trustedProxyHeadersConfigKey, []string{
				"127.0.0.1",
				"172.16.0.0/12",
				"192.168.0.0/16",
			})

			vp.updateTrustedProxies()

			assert.False(t, vp.IsProxyTrusted(net.ParseIP("192.168.0.1")))
		})
	})
}

func TestViperProvider_GetTrustedProxies(t *testing.T) {
	_, n, err := net.ParseCIDR("127.0.0.1/24")
	require.NoError(t, err)

	vp := &viperProvider{
		trustedProxyIPs: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("1.1.2.2"),
		},
		trustedProxyCIDRs: []*net.IPNet{n},
	}

	tp := vp.GetTrustedProxies()
	assert.Len(t, tp, 3)

	assert.Equal(t, "Config File - IP", tp[0].Source)
	assert.Equal(t, "127.0.0.1", tp[0].Description)

	assert.Equal(t, "Config File - IP", tp[1].Source)
	assert.Equal(t, "1.1.2.2", tp[1].Description)

	assert.Equal(t, "Config File - CIDR", tp[2].Source)
	assert.Equal(t, "127.0.0.0/24", tp[2].Description)
}
