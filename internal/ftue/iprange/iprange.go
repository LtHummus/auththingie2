package iprange

import (
	"errors"
	"fmt"
	"net"

	"github.com/rs/zerolog/log"
)

type ipDetector interface {
	GetInterfaces() ([]net.Interface, error)
	GetAddresses(p net.Interface) ([]net.Addr, error)
}

type systemIPDetector struct{}

func (sipd *systemIPDetector) GetInterfaces() ([]net.Interface, error) {
	return net.Interfaces()
}
func (sipd *systemIPDetector) GetAddresses(p net.Interface) ([]net.Addr, error) {
	return p.Addrs()
}

type CandidateRange struct {
	InterfaceName string
	InterfaceIdx  int
	LocalIP       net.IP
	Network       *net.IPNet
}

func DetectInternalIPRange() ([]CandidateRange, error) {
	return internalDetectRange(&systemIPDetector{})
}

func internalDetectRange(detector ipDetector) ([]CandidateRange, error) {
	interfaces, err := detector.GetInterfaces()
	if err != nil {
		return nil, fmt.Errorf("iprange: internalDetectRange: could not enumerate network interfaces: %w", err)
	}

	var ret []CandidateRange
	var detectionErrors []error

	seen := make(map[string]struct{})

	for _, curr := range interfaces {
		if curr.Flags&net.FlagUp == 0 || curr.Flags&net.FlagLoopback != 0 || curr.Flags&net.FlagPointToPoint != 0 {
			continue
		}

		addresses, err := detector.GetAddresses(curr)
		if err != nil {
			detectionErrors = append(detectionErrors, fmt.Errorf("could not enumerate addresses for %s: %w", curr.Name, err))
			continue
		}

		for _, currAddr := range addresses {
			ipNet, ok := currAddr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP
			if !ip.IsPrivate() {
				log.Warn().IPAddr("ip", ip).Msg("rejecting as private")
				continue
			}

			prefixBits, addrBits := ipNet.Mask.Size()
			if prefixBits >= addrBits {
				log.Warn().Int("prefix_bits", prefixBits).Int("addr_bits", addrBits).Str("interface", curr.Name).IPAddr("ip", ip).Msg("skipping due to invalid mask and/or /32")
				continue
			}

			if prefixBits < 8 {
				log.Warn().Int("prefix_bits", prefixBits).Int("addr_bits", addrBits).Str("interface", curr.Name).IPAddr("ip", ip).Msg("skipping due to overly broad")
				continue
			}

			network := &net.IPNet{
				IP:   ip.Mask(ipNet.Mask),
				Mask: append(net.IPMask(nil), ipNet.Mask...),
			}

			key := fmt.Sprintf("%d:%s", curr.Index, network.String())
			if _, exists := seen[key]; exists {
				continue
			}

			seen[key] = struct{}{}

			ret = append(ret, CandidateRange{
				InterfaceName: curr.Name,
				InterfaceIdx:  curr.Index,
				LocalIP:       append(net.IP(nil), ip...),
				Network:       network,
			})
		}
	}

	return ret, errors.Join(detectionErrors...)
}
