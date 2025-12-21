package trueip

import (
	"fmt"
	"net"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

const (
	defaultDockerEndpoint = "unix:///var/run/docker.sock"

	trustedProxyHeadersDockerEndpointConfigKey = "security.trusted_proxies.docker.endpoint"
	trustedProxyHeadersDockerNetworkConfigKey  = "security.trusted_proxies.docker.network"
)

type dockerMonitor struct {
	client    *docker.Client
	endpoint  string
	networkID string
}

func (dm *dockerMonitor) monitorThread() {
	eventChan := make(chan *docker.APIEvents)

	err := dm.client.AddEventListenerWithOptions(docker.EventsOptions{
		Filters: map[string][]string{
			"label": {
				"auththingie2.trusted_proxy",
			},
			"type": {
				"container",
			},
			"event": {
				"die",
				"start",
			},
		},
	}, eventChan)

	if err != nil {
		log.Warn().Err(err).Str("docker_endpoint", dm.endpoint).Msg("could not start listening to docker events")
		return
	}

	for curr := range eventChan {
		fmt.Printf("%#v\n", curr)
	}
}

func startDockerMonitoringThread() {
	dockerEndpoint := viper.GetString(trustedProxyHeadersDockerEndpointConfigKey)
	if dockerEndpoint == "" {
		dockerEndpoint = defaultDockerEndpoint
	}

	dockerNetwork := viper.GetString(trustedProxyHeadersDockerNetworkConfigKey)

	log.Info().Str("docker_endpoint", dockerEndpoint).Str("target_network", dockerNetwork).Msg("starting docker monitoring")

	client, err := docker.NewClient(dockerEndpoint)
	if err != nil {
		log.Warn().Err(err).Str("docker_endpoint", dockerEndpoint).Msg("could not connect to docker")
		return
	}

	dm := &dockerMonitor{
		client:    client,
		endpoint:  dockerEndpoint,
		networkID: dockerNetwork,
	}

	err = dm.findCurrentlyExistingTrustedProxies()
	if err != nil {
		log.Warn().Err(err).Str("docker_endpoint", dm.endpoint).Msg("could not query for existing docker containers")
	}

	go dm.monitorThread()
}

func getIPFromContainer(container *docker.APIContainers, network string) (net.IP, error) {
	for _, curr := range container.Networks.Networks {
		if network == "" || curr.NetworkID == network {
			return net.ParseIP(curr.IPAddress), nil
		}
	}

	return nil, fmt.Errorf("could not find valid IP")
}

func (dm *dockerMonitor) findCurrentlyExistingTrustedProxies() error {
	containers, err := dm.client.ListContainers(docker.ListContainersOptions{
		Filters: map[string][]string{
			"label": {
				"auththingie2.trusted_proxy",
			},
		},
	})
	if err != nil {
		return err
	}

	for _, curr := range containers {
		ip, err := getIPFromContainer(&curr, dm.networkID)
		if err != nil {
			log.Warn().Str("container_id", curr.ID).Str("target_network", dm.networkID).Msg("no IP found")
		} else {
			safeAddToTrustedProxy(ip)
		}
	}

	return nil
}

func safeAddToTrustedProxy(ip net.IP) {
	updateLock.Lock()
	defer updateLock.Unlock()

	for _, curr := range trustedProxyIPs {
		if curr.Equal(ip) {
			return
		}
	}

	trustedProxyIPs = append(trustedProxyIPs, ip)
}

func safeRemoveFromTrustedProxy(ip net.IP) {
	updateLock.Lock()
	defer updateLock.Unlock()

	var cleanedIPs []net.IP
	for _, curr := range trustedProxyIPs {
		if !curr.Equal(ip) {
			cleanedIPs = append(cleanedIPs, curr)
		}
	}

	if len(cleanedIPs) != len(trustedProxyIPs) {
		trustedProxyIPs = cleanedIPs
	}
}
