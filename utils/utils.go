package utils

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/projectcalico/libcalico/lib"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ValidateNetworkName checks that the network name meets felix's expectations
func ValidateNetworkName(name string) error {
	matched, err := regexp.MatchString(`^[a-zA-Z0-9_\.\-]+$`, name)
	if err != nil {
		return err
	}
	if !matched {
		return errors.New("Invalid characters detected in the given network name. " +
			"Only letters a-z, numbers 0-9, and symbols _.- are supported.")
	}
	return nil
}

// AddIgnoreUnknownArgs appends the 'IgnoreUnknown=1' option to CNI_ARGS before calling the IPAM plugin. Otherwise, it will
// complain about the Kubernetes arguments. See https://github.com/kubernetes/kubernetes/pull/24983
func AddIgnoreUnknownArgs() error {
	cniArgs := "IgnoreUnknown=1"
	if os.Getenv("CNI_ARGS") != "" {
		cniArgs = fmt.Sprintf("%s;%s", cniArgs, os.Getenv("CNI_ARGS"))
	}
	return os.Setenv("CNI_ARGS", cniArgs)
}

func CreateResultFromEndpoint(ep *libcalico.Endpoint) (*types.Result, error) {
	result := &types.Result{}

	for _, v := range [][]string{ep.IPv4Nets, ep.IPv6Nets} {
		if len(v) > 0 {
			unparsedIP := fmt.Sprintf(`{"ip": "%s"}`, v[0])
			parsedIP := types.IPConfig{}
			if err := parsedIP.UnmarshalJSON([]byte(unparsedIP)); err != nil {
				return nil, err
			}

			if len(parsedIP.IP.IP) == net.IPv4len {
				result.IP4 = &parsedIP
			} else {
				result.IP6 = &parsedIP
			}
		}
	}

	return result, nil
}

func GetIdentifiers(args *skel.CmdArgs) (workloadID string, orchestratorID string, err error) {
	// Determine if running under k8s by checking the CNI args
	k8sArgs := K8sArgs{}
	if args.Args != "" {
		err := types.LoadArgs(args.Args, &k8sArgs)
		if err != nil {
			return workloadID, orchestratorID, err
		}
	}

	if string(k8sArgs.K8S_POD_NAMESPACE) != "" && string(k8sArgs.K8S_POD_NAME) != "" {
		workloadID = fmt.Sprintf("%s.%s", k8sArgs.K8S_POD_NAMESPACE, k8sArgs.K8S_POD_NAME)
		orchestratorID = "k8s"
	} else {
		workloadID = args.ContainerID
		orchestratorID = "cni"
	}
	return workloadID, orchestratorID, nil
}

func PopulateEndpointNets(endpoint *libcalico.Endpoint, result *types.Result) error {
	if result.IP4 == nil && result.IP6 == nil {
		return errors.New("IPAM plugin did not return any IP addresses")
	}

	if result.IP4 != nil {
		result.IP4.IP.Mask = net.CIDRMask(32, 32)
		endpoint.IPv4Nets = []string{result.IP4.IP.String()}
	} else {
		endpoint.IPv4Nets = []string{}
	}

	if result.IP6 != nil {
		result.IP6.IP.Mask = net.CIDRMask(128, 128)
		endpoint.IPv6Nets = []string{result.IP6.IP.String()}
	} else {
		endpoint.IPv6Nets = []string{}
	}
	return nil
}
