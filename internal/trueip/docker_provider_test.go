package trueip

import (
	"errors"
	"net"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/lthummus/auththingie2/internal/mocks"
)

func TestDockerProvider_IsProxyTrusted(t *testing.T) {
	t.Run("happy case", func(t *testing.T) {
		dp := dockerProvider{
			activeIPs: map[string][]net.IP{
				"test-container": {
					net.ParseIP("127.0.0.1"),
					net.ParseIP("127.0.0.5"),
				},
			},
		}

		assert.True(t, dp.IsProxyTrusted(net.ParseIP("127.0.0.1")))
		assert.True(t, dp.IsProxyTrusted(net.ParseIP("127.0.0.5")))
		assert.False(t, dp.IsProxyTrusted(net.ParseIP("127.0.0.4")))
	})
}

func TestDockerProvider_GetTrustedProxies(t *testing.T) {
	t.Run("happy case", func(t *testing.T) {
		dp := dockerProvider{
			activeIPs: map[string][]net.IP{
				"test-container": {
					net.ParseIP("127.0.0.1"),
					net.ParseIP("127.0.0.5"),
				},
				"test-container-2": {
					net.ParseIP("127.0.0.9"),
				},
			},
		}

		tp := dp.GetTrustedProxies()

		assert.Len(t, tp, 3)
		assert.Contains(t, tp, TrustedProxy{Source: "Docker - Container test-container", Description: "127.0.0.1"})
		assert.Contains(t, tp, TrustedProxy{Source: "Docker - Container test-container", Description: "127.0.0.5"})
		assert.Contains(t, tp, TrustedProxy{Source: "Docker - Container test-container-2", Description: "127.0.0.9"})
	})
}

func TestDockerProvider_updateIPs(t *testing.T) {
	t.Run("happy case", func(t *testing.T) {
		mockDocker := mocks.NewMockDockerAPI(t)
		dp := &dockerProvider{
			client:    mockDocker,
			activeIPs: map[string][]net.IP{},
		}

		mockDocker.On("ContainerList", mock.AnythingOfType("*context.cancelCtx"), mock.AnythingOfType("container.ListOptions")).Return([]container.Summary{
			{
				ID: "test-container-id",
			},
			{
				ID: "test-container-id2",
			},
		}, nil)
		mockDocker.On("ContainerInspect", mock.AnythingOfType("*context.cancelCtx"), "test-container-id").Return(container.InspectResponse{
			NetworkSettings: &container.NetworkSettings{
				Networks: map[string]*network.EndpointSettings{
					"sample-network": {
						IPAddress: "127.0.0.1",
					},
				},
			},
		}, nil)
		mockDocker.On("ContainerInspect", mock.AnythingOfType("*context.cancelCtx"), "test-container-id2").Return(container.InspectResponse{
			NetworkSettings: &container.NetworkSettings{
				Networks: map[string]*network.EndpointSettings{
					"sample-network": {
						IPAddress: "127.0.0.2",
					},
					"sample-network2": {
						IPAddress: "127.0.0.3",
					},
				},
			},
		}, nil)

		assert.Empty(t, dp.activeIPs)

		dp.updateIPs(t.Context())

		containerIPs := dp.activeIPs["test-container-id"]
		assert.Len(t, containerIPs, 1)
		assert.Equal(t, net.ParseIP("127.0.0.1"), containerIPs[0])

		containerIPs2 := dp.activeIPs["test-container-id2"]
		assert.Len(t, containerIPs2, 2)
		assert.Contains(t, containerIPs2, net.ParseIP("127.0.0.2"))
		assert.Contains(t, containerIPs2, net.ParseIP("127.0.0.3"))
	})

	t.Run("error on query", func(t *testing.T) {
		mockDocker := mocks.NewMockDockerAPI(t)
		dp := &dockerProvider{
			client:    mockDocker,
			activeIPs: map[string][]net.IP{},
		}

		mockDocker.On("ContainerList", mock.AnythingOfType("*context.cancelCtx"), mock.AnythingOfType("container.ListOptions")).Return(nil, errors.New("something went wrong"))

		dp.updateIPs(t.Context())

		assert.Empty(t, dp.activeIPs)
	})

	t.Run("error on container query", func(t *testing.T) {
		mockDocker := mocks.NewMockDockerAPI(t)
		dp := &dockerProvider{
			client:    mockDocker,
			activeIPs: map[string][]net.IP{},
		}

		mockDocker.On("ContainerList", mock.AnythingOfType("*context.cancelCtx"), mock.AnythingOfType("container.ListOptions")).Return([]container.Summary{
			{
				ID: "test-container-id",
			},
		}, nil)
		mockDocker.On("ContainerInspect", mock.AnythingOfType("*context.cancelCtx"), "test-container-id").Return(container.InspectResponse{}, errors.New("something went wrong"))

		assert.Empty(t, dp.activeIPs)

		dp.updateIPs(t.Context())

		assert.Empty(t, dp.activeIPs)

	})

	t.Run("unparseable IP", func(t *testing.T) {
		mockDocker := mocks.NewMockDockerAPI(t)
		dp := &dockerProvider{
			client:    mockDocker,
			activeIPs: map[string][]net.IP{},
		}

		mockDocker.On("ContainerList", mock.AnythingOfType("*context.cancelCtx"), mock.AnythingOfType("container.ListOptions")).Return([]container.Summary{
			{
				ID: "test-container-id",
			},
		}, nil)
		mockDocker.On("ContainerInspect", mock.AnythingOfType("*context.cancelCtx"), "test-container-id").Return(container.InspectResponse{
			NetworkSettings: &container.NetworkSettings{
				Networks: map[string]*network.EndpointSettings{
					"sample-network": {
						IPAddress: "aaaaa",
					},
				},
			},
		}, nil)

		assert.Empty(t, dp.activeIPs)

		dp.updateIPs(t.Context())

		assert.Empty(t, dp.activeIPs["test-container-id"])
	})
}

func TestDockerProvider_eventListener(t *testing.T) {

}
