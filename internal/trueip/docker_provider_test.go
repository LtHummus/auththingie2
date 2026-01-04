package trueip

import (
	"context"
	_ "embed"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/network"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/lthummus/auththingie2/internal/mocks"
)

//go:embed testdata/sample_docker_info.json
var sampleDockerInfoResponse []byte

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
	t.Run("happy case", func(t *testing.T) {
		mockDocker := mocks.NewMockDockerAPI(t)
		dp := &dockerProvider{
			client:    mockDocker,
			activeIPs: map[string][]net.IP{},
		}

		synctest.Test(t, func(t *testing.T) {
			eventStream := make(chan events.Message)
			errorStream := make(chan error)

			mockDocker.On("Events", mock.Anything, mock.AnythingOfType("events.ListOptions")).
				Return((<-chan events.Message)(eventStream), (<-chan error)(errorStream))
			mockDocker.On("ContainerInspect", mock.Anything, "test-container-id").Return(container.InspectResponse{
				NetworkSettings: &container.NetworkSettings{
					Networks: map[string]*network.EndpointSettings{
						"sample-network": {
							IPAddress: "127.0.0.1",
						},
					},
				},
			}, nil)

			ctx, cancel := context.WithCancel(t.Context())

			go dp.eventListener(ctx)

			eventStream <- events.Message{
				Action: events.ActionStart,
				Actor: events.Actor{
					ID: "test-container-id",
				},
			}

			synctest.Wait()

			assert.Len(t, dp.activeIPs, 1)
			assert.Len(t, dp.activeIPs["test-container-id"], 1)
			assert.Equal(t, net.ParseIP("127.0.0.1"), dp.activeIPs["test-container-id"][0])

			cancel()
		})

	})

	t.Run("a couple of events", func(t *testing.T) {
		mockDocker := mocks.NewMockDockerAPI(t)
		dp := &dockerProvider{
			client:    mockDocker,
			activeIPs: map[string][]net.IP{},
		}

		synctest.Test(t, func(t *testing.T) {
			eventStream := make(chan events.Message)
			errorStream := make(chan error)

			mockDocker.On("Events", mock.Anything, mock.AnythingOfType("events.ListOptions")).
				Return((<-chan events.Message)(eventStream), (<-chan error)(errorStream))
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
					},
				},
			}, nil)

			ctx, cancel := context.WithCancel(t.Context())

			go dp.eventListener(ctx)

			eventStream <- events.Message{
				Action: events.ActionStart,
				Actor: events.Actor{
					ID: "test-container-id",
				},
			}

			synctest.Wait()

			assert.Len(t, dp.activeIPs, 1)
			assert.Len(t, dp.activeIPs["test-container-id"], 1)
			assert.Equal(t, net.ParseIP("127.0.0.1"), dp.activeIPs["test-container-id"][0])

			eventStream <- events.Message{
				Action: events.ActionStart,
				Actor: events.Actor{
					ID: "test-container-id2",
				},
			}

			synctest.Wait()

			assert.Len(t, dp.activeIPs, 2)
			assert.Len(t, dp.activeIPs["test-container-id"], 1)
			assert.Equal(t, net.ParseIP("127.0.0.1"), dp.activeIPs["test-container-id"][0])
			assert.Len(t, dp.activeIPs["test-container-id2"], 1)
			assert.Equal(t, net.ParseIP("127.0.0.2"), dp.activeIPs["test-container-id2"][0])

			eventStream <- events.Message{
				Action: events.ActionDie,
				Actor: events.Actor{
					ID: "test-container-id",
				},
			}

			synctest.Wait()

			assert.Len(t, dp.activeIPs, 1)
			assert.Empty(t, dp.activeIPs["test-container-id"])
			assert.Len(t, dp.activeIPs["test-container-id2"], 1)
			assert.Equal(t, net.ParseIP("127.0.0.2"), dp.activeIPs["test-container-id2"][0])

			cancel()
		})

	})

	t.Run("error handling and disconnection", func(t *testing.T) {
		mockDocker := mocks.NewMockDockerAPI(t)
		dp := &dockerProvider{
			client:    mockDocker,
			activeIPs: map[string][]net.IP{},
		}

		synctest.Test(t, func(t *testing.T) {
			eventStream := make(chan events.Message)
			errorStream := make(chan error)

			mockDocker.On("Events", mock.Anything, mock.AnythingOfType("events.ListOptions")).
				Return((<-chan events.Message)(eventStream), (<-chan error)(errorStream))
			mockDocker.On("DaemonHost").Return("localhost")

			ctx, cancel := context.WithCancel(t.Context())

			go dp.eventListener(ctx)

			errorStream <- errors.New("hi")

			cancel()
		})

		assert.Len(t, mockDocker.Calls, 3) // Events twice, DaemonHost once

	})
}

func TestDockerProvider_Active(t *testing.T) {
	dp := &dockerProvider{}

	assert.False(t, dp.Active())

	dp.eventStreamInitialized = true

	assert.True(t, dp.Active())
}

func TestDockerProvider_ContainsProxies(t *testing.T) {
	dp := &dockerProvider{}
	assert.False(t, dp.ContainsProxies())

	dp.activeIPs = map[string][]net.IP{
		"test": {
			net.ParseIP("1.1.1.1"),
		},
	}
	assert.True(t, dp.ContainsProxies())
}

func TestDockerProvider_newDockerProvider(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		dp := newDockerProvider(t.Context())
		assert.Nil(t, dp)
	})

	t.Run("sample init", func(t *testing.T) {
		t.Cleanup(func() {
			viper.Reset()
		})

		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())

			// this is my little fake docker endpoint. Is this a good idea? Not sure!
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/_ping" {
					w.Header().Set("Api-Version", "1.47")
					w.Header().Set("Builder-Version", "2")
					w.Header().Set("Docker-Experimental", "false")
					w.Header().Set("Ostype", "linux")
					w.Header().Set("Server", "Docker/27.2.0 (linux)")
					w.Header().Set("Swarm", "inactive")
					w.Write(nil)
				} else if r.URL.Path == "/v1.47/info" {
					w.Header().Set("Content-Type", "application/json")
					w.Write(sampleDockerInfoResponse)
				} else if r.URL.Path == "/v1.47/containers/json" {
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(`[]`))
				} else if r.URL.Path == "/v1.47/events" {

				} else {
					t.Fatalf("unknown docker endpoint called: %s", r.URL.Path)
				}
			}))

			viper.Set(trustedProxyDockerEnabledConfigKey, true)
			viper.Set(trustedProxyDockerEndpointConfigKey, srv.URL)

			dp := newDockerProvider(ctx)
			assert.NotNil(t, dp)

			cancel()
			srv.Close()

			synctest.Wait()

		})

	})
}

func TestDockerProvider_Teardown(t *testing.T) {
	t.Run("basic functionality", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			mockDocker := mocks.NewMockDockerAPI(t)
			dp := &dockerProvider{
				cleanup:   make(chan struct{}),
				activeIPs: map[string][]net.IP{},
				client:    mockDocker,
			}

			eventStream := make(chan events.Message)
			errorStream := make(chan error)

			mockDocker.On("Events", mock.Anything, mock.AnythingOfType("events.ListOptions")).
				Return((<-chan events.Message)(eventStream), (<-chan error)(errorStream))
			mockDocker.On("Close").Run(func(args mock.Arguments) {
				close(eventStream)
				close(errorStream)
			}).Return(nil)

			go dp.eventListener(t.Context())
			synctest.Wait()

			err := dp.Teardown(t.Context())
			assert.NoError(t, err)

			// this is the best way i found to determine if the inner context (that has been wrapped with a cancel signal)
			// has actually been closed on cleanup
			innerCtx := mockDocker.Calls[0].Arguments[0].(context.Context)
			_, open := <-innerCtx.Done()
			assert.False(t, open)

		})

	})
}
