package iprange

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetectInternalIPRange(t *testing.T) {
	interfaces, err := DetectInternalIPRange()
	require.NoError(t, err)

	for _, curr := range interfaces {
		fmt.Printf("%s -- %s -- %s\n", curr.InterfaceName, curr.LocalIP.String(), curr.Network.String())
	}
}
