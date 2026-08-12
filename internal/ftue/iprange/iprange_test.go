package iprange

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lthummus/auththingie2/internal/mocks"
)

func makeNetInterface(idx int, name string, flags net.Flags) net.Interface {
	return net.Interface{
		Index: idx,
		Name:  name,
		Flags: flags,
	}
}

func makeIPNet(cidr string) *net.IPNet {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}

	return &net.IPNet{
		IP:   ip,
		Mask: network.Mask,
	}
}

type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }
func (fakeAddr) String() string  { return "not-an-ipnet" }

func rangeEquals(t *testing.T, got CandidateRange, name string, idx int, localIP string, network string) {
	t.Helper()

	assert.Equal(t, name, got.InterfaceName)
	assert.Equal(t, idx, got.InterfaceIdx)
	assert.Equal(t, localIP, got.LocalIP.String())
	require.NotNil(t, got.Network)
	assert.Equal(t, network, got.Network.String())
}

func TestInternalDetectRange(t *testing.T) {
	t.Run("happy case, one private range found", func(t *testing.T) {
		eth0 := makeNetInterface(1, "eth0", net.FlagUp|net.FlagBroadcast)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{eth0}, nil)
		detector.On("GetAddresses", eth0).Return([]net.Addr{makeIPNet("192.168.1.5/24")}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)

		require.Len(t, ranges, 1)
		rangeEquals(t, ranges[0], "eth0", 1, "192.168.1.5", "192.168.1.0/24")
	})

	t.Run("multiple interfaces, ordering preserved", func(t *testing.T) {
		eth0 := makeNetInterface(1, "eth0", net.FlagUp|net.FlagBroadcast)
		eth1 := makeNetInterface(2, "eth1", net.FlagUp|net.FlagBroadcast)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{eth0, eth1}, nil)
		detector.On("GetAddresses", eth0).Return([]net.Addr{makeIPNet("10.1.2.3/16")}, nil)
		detector.On("GetAddresses", eth1).Return([]net.Addr{makeIPNet("172.16.5.4/20")}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)

		require.Len(t, ranges, 2)
		rangeEquals(t, ranges[0], "eth0", 1, "10.1.2.3", "10.1.0.0/16")
		rangeEquals(t, ranges[1], "eth1", 2, "172.16.5.4", "172.16.0.0/20")
	})

	t.Run("multiple addresses on one interface", func(t *testing.T) {
		eth0 := makeNetInterface(1, "eth0", net.FlagUp|net.FlagBroadcast)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{eth0}, nil)
		detector.On("GetAddresses", eth0).Return([]net.Addr{
			makeIPNet("192.168.1.5/24"),
			makeIPNet("fd00::1/64"),
		}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)

		require.Len(t, ranges, 2)
		rangeEquals(t, ranges[0], "eth0", 1, "192.168.1.5", "192.168.1.0/24")
		rangeEquals(t, ranges[1], "eth0", 1, "fd00::1", "fd00::/64")
	})

	t.Run("no interfaces at all", func(t *testing.T) {
		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)
		assert.Nil(t, ranges)
	})

	t.Run("interface with no addresses", func(t *testing.T) {
		eth0 := makeNetInterface(1, "eth0", net.FlagUp|net.FlagBroadcast)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{eth0}, nil)
		detector.On("GetAddresses", eth0).Return([]net.Addr{}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)
		assert.Nil(t, ranges)
	})

	t.Run("skips interfaces that are down", func(t *testing.T) {
		eth0 := makeNetInterface(1, "eth0", 0)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{eth0}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)
		assert.Empty(t, ranges)
	})

	t.Run("skips loopback interfaces", func(t *testing.T) {
		lo := makeNetInterface(1, "lo0", net.FlagUp|net.FlagLoopback)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{lo}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)
		assert.Empty(t, ranges)
	})

	t.Run("skips point to point interfaces", func(t *testing.T) {
		tun0 := makeNetInterface(1, "tun0", net.FlagUp|net.FlagPointToPoint)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{tun0}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)
		assert.Empty(t, ranges)
	})

	t.Run("error enumerating interfaces", func(t *testing.T) {
		sentinel := errors.New("oh no")

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return(nil, sentinel)

		ranges, err := internalDetectRange(detector)
		assert.Nil(t, ranges)
		assert.ErrorIs(t, err, sentinel)
		assert.ErrorContains(t, err, "could not enumerate network interfaces")
	})

	t.Run("error enumerating addresses on one interface", func(t *testing.T) {
		eth0 := makeNetInterface(1, "eth0", net.FlagUp|net.FlagBroadcast)
		eth1 := makeNetInterface(2, "eth1", net.FlagUp|net.FlagBroadcast)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{eth0, eth1}, nil)
		detector.On("GetAddresses", eth0).Return(nil, errors.New("oh no"))
		detector.On("GetAddresses", eth1).Return([]net.Addr{makeIPNet("192.168.1.5/24")}, nil)

		ranges, err := internalDetectRange(detector)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "could not enumerate addresses for eth0")

		require.Len(t, ranges, 1)
		rangeEquals(t, ranges[0], "eth1", 2, "192.168.1.5", "192.168.1.0/24")
	})

	t.Run("all interfaces fail address enumeration", func(t *testing.T) {
		firstError := errors.New("oh no")
		secondError := errors.New("oh no, again")
		eth0 := makeNetInterface(1, "eth0", net.FlagUp|net.FlagBroadcast)
		eth1 := makeNetInterface(2, "eth1", net.FlagUp|net.FlagBroadcast)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{eth0, eth1}, nil)
		detector.On("GetAddresses", eth0).Return(nil, firstError)
		detector.On("GetAddresses", eth1).Return(nil, secondError)

		ranges, err := internalDetectRange(detector)
		assert.Nil(t, ranges)
		assert.ErrorIs(t, err, firstError)
		assert.ErrorIs(t, err, secondError)
	})

	t.Run("skips non-IPNet addresses", func(t *testing.T) {
		eth0 := makeNetInterface(1, "eth0", net.FlagUp|net.FlagBroadcast)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{eth0}, nil)
		detector.On("GetAddresses", eth0).Return([]net.Addr{
			fakeAddr{},
			makeIPNet("192.168.1.5/24"),
		}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)

		require.Len(t, ranges, 1)
		rangeEquals(t, ranges[0], "eth0", 1, "192.168.1.5", "192.168.1.0/24")
	})

	t.Run("skips public IPs", func(t *testing.T) {
		eth0 := makeNetInterface(1, "eth0", net.FlagUp|net.FlagBroadcast)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{eth0}, nil)
		detector.On("GetAddresses", eth0).Return([]net.Addr{makeIPNet("8.8.8.8/24")}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)
		assert.Empty(t, ranges)
	})

	t.Run("skips public IPv6", func(t *testing.T) {
		eth0 := makeNetInterface(1, "eth0", net.FlagUp|net.FlagBroadcast)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{eth0}, nil)
		detector.On("GetAddresses", eth0).Return([]net.Addr{makeIPNet("2606:4700::1/64")}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)
		assert.Empty(t, ranges)
	})

	t.Run("skips /32 addresses", func(t *testing.T) {
		eth0 := makeNetInterface(1, "eth0", net.FlagUp|net.FlagBroadcast)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{eth0}, nil)
		detector.On("GetAddresses", eth0).Return([]net.Addr{makeIPNet("192.168.1.5/32")}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)
		assert.Empty(t, ranges)
	})

	t.Run("skips overly broad ranges", func(t *testing.T) {
		eth0 := makeNetInterface(1, "eth0", net.FlagUp|net.FlagBroadcast)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{eth0}, nil)
		detector.On("GetAddresses", eth0).Return([]net.Addr{makeIPNet("10.0.0.1/7")}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)
		assert.Empty(t, ranges)
	})

	t.Run("accepts IPv6 unique local addresses", func(t *testing.T) {
		eth0 := makeNetInterface(1, "eth0", net.FlagUp|net.FlagBroadcast)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{eth0}, nil)
		detector.On("GetAddresses", eth0).Return([]net.Addr{makeIPNet("fd00::1/64")}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)

		require.Len(t, ranges, 1)
		rangeEquals(t, ranges[0], "eth0", 1, "fd00::1", "fd00::/64")
	})

	t.Run("de-duplicates identical network on same interface", func(t *testing.T) {
		eth0 := makeNetInterface(1, "eth0", net.FlagUp|net.FlagBroadcast)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{eth0}, nil)
		detector.On("GetAddresses", eth0).Return([]net.Addr{
			makeIPNet("192.168.1.5/24"),
			makeIPNet("192.168.1.6/24"),
		}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)

		require.Len(t, ranges, 1)
		rangeEquals(t, ranges[0], "eth0", 1, "192.168.1.5", "192.168.1.0/24")
	})

	t.Run("same network on different interfaces is kept", func(t *testing.T) {
		eth0 := makeNetInterface(1, "eth0", net.FlagUp|net.FlagBroadcast)
		eth1 := makeNetInterface(2, "eth1", net.FlagUp|net.FlagBroadcast)

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{eth0, eth1}, nil)
		detector.On("GetAddresses", eth0).Return([]net.Addr{makeIPNet("192.168.1.5/24")}, nil)
		detector.On("GetAddresses", eth1).Return([]net.Addr{makeIPNet("192.168.1.5/24")}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)

		require.Len(t, ranges, 2)
		rangeEquals(t, ranges[0], "eth0", 1, "192.168.1.5", "192.168.1.0/24")
		rangeEquals(t, ranges[1], "eth1", 2, "192.168.1.5", "192.168.1.0/24")
	})

	t.Run("exact duplicate address repeated", func(t *testing.T) {
		eth0 := makeNetInterface(1, "eth0", net.FlagUp|net.FlagBroadcast)
		addr := makeIPNet("192.168.1.5/24")

		detector := mocks.NewMockIPDetector(t)
		detector.On("GetInterfaces").Return([]net.Interface{eth0}, nil)
		detector.On("GetAddresses", eth0).Return([]net.Addr{addr, addr}, nil)

		ranges, err := internalDetectRange(detector)
		require.NoError(t, err)

		require.Len(t, ranges, 1)
		rangeEquals(t, ranges[0], "eth0", 1, "192.168.1.5", "192.168.1.0/24")
	})
}
