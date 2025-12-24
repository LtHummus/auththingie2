package trueip

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	dockerclient "github.com/docker/docker/client"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/notices"
)

const (
	trustedProxyDockerEnabledConfigKey  = "security.trusted_proxies.docker.enabled"
	trustedProxyDockerEndpointConfigKey = "security.trusted_proxies.docker.endpoint"

	defaultDockerEndpoint = "unix:///var/run/docker.sock"
)

var tagFilter = filters.NewArgs(
	filters.Arg("label", "auththingie2.trusted_proxy=true"),
	filters.Arg("status", "running"),
)

var eventFilter = filters.NewArgs(
	filters.Arg("label", "auththingie2.trusted_proxy=true"),
	filters.Arg("type", "container"),
	filters.Arg("event", "die"),
	filters.Arg("event", "start"),
)

type dockerAPI interface {
	Events(ctx context.Context, options events.ListOptions) (<-chan events.Message, <-chan error)
	ContainerList(ctx context.Context, options container.ListOptions) ([]container.Summary, error)
	ContainerInspect(ctx context.Context, containerID string) (container.InspectResponse, error)

	DaemonHost() string
	ClientVersion() string
}

type dockerProvider struct {
	client dockerAPI

	eventStreamInitialized bool
	activeIPs              map[string][]net.IP
	updateLock             sync.RWMutex
	lastUpdate             time.Time
}

func (dp *dockerProvider) Active() bool {
	return dp.eventStreamInitialized
}

func newDockerProvider(ctx context.Context) *dockerProvider {
	if !viper.GetBool(trustedProxyDockerEnabledConfigKey) {
		return nil
	}

	dockerEndpoint := viper.GetString(trustedProxyDockerEndpointConfigKey)
	if dockerEndpoint == "" {
		dockerEndpoint = defaultDockerEndpoint
	}

	dockerClient, err := dockerclient.NewClientWithOpts(dockerclient.WithHost(dockerEndpoint), dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		log.Warn().Err(err).Str("docker_endpoint", dockerEndpoint).Msg("could not connect to docker")
		return nil
	}

	_, err = dockerClient.Info(ctx)
	if err != nil {
		log.Error().Err(err).Str("docker_endpoint", dockerClient.DaemonHost()).Msg("could not query docker info")
		notices.AddMessage("docker-misconfigure", "Could not contact docker daemon to check for proxies. Look at logs")
		return nil
	}

	log.Info().Str("docker_endpoint", dockerClient.DaemonHost()).Str("api_version", dockerClient.ClientVersion()).Msg("connected to docker daemon")

	dp := &dockerProvider{
		client:    dockerClient,
		activeIPs: map[string][]net.IP{},
	}

	go dp.eventListener(ctx)

	err = dp.updateIPs(ctx)
	if err != nil {
		notices.AddMessage("docker-invalid", "Could not contact and query the docker daemon. Check the logs")
		log.Error().Err(err).Msg("could not contact docker daemon for initial query")
		return nil
	}

	return dp
}

func (dp *dockerProvider) updateIPs(ctx context.Context) error {
	dp.updateLock.Lock()
	defer dp.updateLock.Unlock()

	resp, err := dp.client.ContainerList(ctx, container.ListOptions{
		Filters: tagFilter,
	})

	if err != nil {
		log.Error().Err(err).Msg("could not query running containers from API")
		return err
	}

	for _, curr := range resp {
		netIPs, err := dp.getDockerIPs(ctx, curr.ID)
		if err != nil {
			log.Warn().Err(err).Str("container_id", curr.ID).Msg("could not get container IP addresses")
			continue
		}
		dp.activeIPs[curr.ID] = netIPs
	}

	log.Info().Int("num_containers", len(dp.activeIPs)).Msg("found active proxies from docker")

	return nil
}

func (dp *dockerProvider) eventListener(ctx context.Context) {
	for {
		eventStream, errorStream := dp.client.Events(ctx, events.ListOptions{
			Filters: eventFilter,
		})

		dp.eventStreamInitialized = true

		log.Info().Msg("docker event stream connected")
		shouldContinue := dp.listenToDockerStreams(ctx, eventStream, errorStream)
		if !shouldContinue {
			log.Warn().Msg("got cleanup signal. no longer listening to docker events")
			dp.eventStreamInitialized = false
			break
		}
	}
}

func (dp *dockerProvider) listenToDockerStreams(ctx context.Context, eventStream <-chan events.Message, errorStream <-chan error) bool {
	for {
		select {
		case evt := <-eventStream:
			dp.handleDockerEvent(ctx, evt)
		case err := <-errorStream:
			log.Warn().Err(err).Str("docker_endpoint", dp.client.DaemonHost()).Msg("connection to docker lost, reconnecting")
			return true
		case <-ctx.Done():
			return false
		}
	}
}

func (dp *dockerProvider) handleDockerEvent(ctx context.Context, event events.Message) {
	log.Debug().Str("action", string(event.Action)).Str("container_id", event.Actor.ID).Msg("got docker event")

	if event.Action == events.ActionStart {
		ips, err := dp.getDockerIPs(ctx, event.Actor.ID)
		if err != nil {
			log.Warn().Err(err).Str("container_id", event.Actor.ID).Msg("could not query for IP addresses")
		}
		dp.updateLock.Lock()
		dp.activeIPs[event.Actor.ID] = ips
		dp.updateLock.Unlock()
	} else if event.Action == events.ActionDie {
		dp.updateLock.Lock()
		delete(dp.activeIPs, event.Actor.ID)
		dp.updateLock.Unlock()
	} else {
		log.Warn().Str("container_id", event.Actor.ID).Str("action", string(event.Action)).Msg("unknown docker action")
	}
}

func (dp *dockerProvider) getDockerIPs(ctx context.Context, containerID string) ([]net.IP, error) {
	resp, err := dp.client.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, err
	}

	var ret []net.IP

	for _, curr := range resp.NetworkSettings.Networks {
		ip := net.ParseIP(curr.IPAddress)
		if ip == nil {
			log.Error().Str("ip_string", curr.IPAddress).Str("container_id", containerID).Msg("could not parse container IP address")
			continue
		}

		ret = append(ret, ip)
	}

	if len(ret) == 0 {
		log.Warn().Str("container_id", containerID).Msg("no network IP addresses found")
	}

	for _, curr := range ret {
		log.Debug().Str("container_id", containerID).IPAddr("ip", curr).Msg("found docker proxy IP")
	}

	return ret, nil
}

func (dp *dockerProvider) IsProxyTrusted(ip net.IP) bool {
	dp.updateLock.RLock()
	defer dp.updateLock.RUnlock()

	for _, containerIPs := range dp.activeIPs {
		for _, curr := range containerIPs {
			if ip.Equal(curr) {
				return true
			}
		}
	}

	return false
}

func (dp *dockerProvider) ContainsProxies() bool {
	dp.updateLock.RLock()
	defer dp.updateLock.RUnlock()

	return len(dp.activeIPs) > 0
}

func (dp *dockerProvider) GetTrustedProxies() []TrustedProxy {
	dp.updateLock.RLock()
	defer dp.updateLock.RUnlock()

	var ret []TrustedProxy

	for id, ips := range dp.activeIPs {
		for _, curr := range ips {
			ret = append(ret, TrustedProxy{
				Source:      fmt.Sprintf("Docker - Container %s", id),
				Description: curr.String(),
			})
		}
	}

	return ret
}
