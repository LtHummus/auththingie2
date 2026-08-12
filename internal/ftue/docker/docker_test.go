package docker

import (
	"errors"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/lthummus/auththingie2/internal/mocks"
)

func TestInternalDetectDocker(t *testing.T) {
	t.Run("happy case, a container found!", func(t *testing.T) {
		mockDocker := mocks.NewMockFTUEDockerAPI(t)

		mockDocker.On("ContainerList", mock.Anything, mock.Anything).Return([]container.Summary{
			{
				ID:    "sample-container-one",
				Names: []string{"sample"},
			},
		}, nil)

		containers, err := internalDetectDocker(t.Context(), mockDocker)
		require.NoError(t, err)

		listOptions := mockDocker.Calls[0].Arguments[1].(container.ListOptions)
		assert.NotEmpty(t, listOptions.Filters)
		assert.Equal(t, "auththingie2.trusted_proxy=true", listOptions.Filters.Get("label")[0])
		assert.Equal(t, "running", listOptions.Filters.Get("status")[0])

		require.Len(t, containers, 1)
		assert.Equal(t, "sample-container-one", containers[0].ID)
		require.Len(t, containers[0].Name, 1)
		assert.Equal(t, "sample", containers[0].Name[0])
	})

	t.Run("some error when listing", func(t *testing.T) {
		mockDocker := mocks.NewMockFTUEDockerAPI(t)

		mockDocker.On("ContainerList", mock.Anything, mock.Anything).Return(nil, errors.New("oh no"))

		containers, err := internalDetectDocker(t.Context(), mockDocker)
		assert.Nil(t, containers)
		assert.ErrorIs(t, err, &ErrCouldNotList{})
	})

	t.Run("no containers found", func(t *testing.T) {
		mockDocker := mocks.NewMockFTUEDockerAPI(t)

		mockDocker.On("ContainerList", mock.Anything, mock.Anything).Return([]container.Summary{}, nil)

		containers, err := internalDetectDocker(t.Context(), mockDocker)
		require.NoError(t, err)
		assert.Empty(t, containers)
	})
}
