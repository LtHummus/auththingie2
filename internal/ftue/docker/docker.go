package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	dockerclient "github.com/docker/docker/client"
	"github.com/rs/zerolog/log"
)

const (
	DefaultDockerEndpoint = "unix:///var/run/docker.sock"
)

type ErrNoDockerEndpoint struct{}

func (*ErrNoDockerEndpoint) Error() string { return "no docker endpoint at the usual place" }

type ErrCouldNotList struct {
	Cause error
}

func (ecnl *ErrCouldNotList) Error() string {
	if ecnl.Cause == nil {
		return "could not list containers for some unknown reason"
	}
	return fmt.Sprintf("could not list containers: %s", ecnl.Cause.Error())
}

type FoundContainer struct {
	ID    string
	Name  []string
	Image string
}

func (fc *FoundContainer) AllNames() string {
	return strings.Join(fc.Name, ", ")
}

func (fc *FoundContainer) ShortID() string {
	count := 12
	if count > len(fc.ID) {
		count = len(fc.ID)
	}
	return fc.ID[:count]
}

type dockerAPI interface {
	ContainerList(context.Context, container.ListOptions) ([]container.Summary, error)
	Close() error
}

func DetectDocker(ctx context.Context, dockerEndpoint string) ([]FoundContainer, error) {
	client, err := dockerclient.NewClientWithOpts(dockerclient.WithHost(dockerEndpoint), dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		log.Warn().Err(err).Msg("could not connect to docker endpoint")
		return nil, &ErrNoDockerEndpoint{}
	}
	defer client.Close()

	log.Info().Str("docker_endpoint", dockerEndpoint).Msg("attempting to detect some docker containers")

	return internalDetectDocker(ctx, client)
}

func internalDetectDocker(ctx context.Context, client dockerAPI) ([]FoundContainer, error) {
	containers, err := client.ContainerList(ctx, container.ListOptions{
		Filters: filters.NewArgs(
			filters.Arg("label", "auththingie2.trusted_proxy=true"),
			filters.Arg("status", "running"),
		),
	})
	if err != nil {
		log.Warn().Err(err).Msg("could not list docker containers")
		return nil, &ErrCouldNotList{Cause: err}
	}

	ret := make([]FoundContainer, len(containers))

	for i, curr := range containers {
		log.Info().Str("container_id", curr.ID).Msg("found tagged containers")
		ret[i] = FoundContainer{
			ID:    curr.ID,
			Name:  curr.Names,
			Image: curr.Image,
		}
	}

	return ret, nil
}
