package main

import (
	"encoding/json"
	"fmt"
	"net"

	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/projectcalico/calico-cni/utils"
	"github.com/projectcalico/libcalico/lib/ipam"
)

func main() {
	skel.PluginMain(cmdAdd, cmdDel)
}

// ipamConfig represents the IP related network configuration.
type ipamConfig struct {
	Name       string
	Type       string  `json:"type"`
	AssignIpv4 *string `json:"assign_ipv4"`
	AssignIpv6 *string `json:"assign_ipv6"`
}

type ipamArgs struct {
	types.CommonArgs
	IP net.IP `json:"ip,omitempty"`
}

type netConf struct {
	Name          string      `json:"name"`
	EtcdAuthority string      `json:"etcd_authority"`
	EtcdEndpoints string      `json:"etcd_endpoints"`
	Hostname      *string     `json:"hostname"`
	IPAM          *ipamConfig `json:"ipam"`
	Args          *ipamArgs   `json:"-"`
}

func loadIPAMConfig(bytes []byte, args string) (*netConf, error) {
	n := &netConf{}
	if err := json.Unmarshal(bytes, &n); err != nil {
		return nil, err
	}

	if args != "" {
		n.Args = &ipamArgs{}
		err := types.LoadArgs(args, n.Args)
		if err != nil {
			return nil, err
		}
	}

	if n.IPAM == nil {
		return nil, fmt.Errorf("missing 'ipam' key")
	}

	return n, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := loadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	ipamClient, err := ipam.NewIPAMClient()
	if err != nil {
		return err
	}

	workloadID, _, err := utils.GetIdentifiers(args)
	if err != nil {
		return err
	}

	r := &types.Result{}
	if conf.Args != nil && conf.Args.IP != nil {
		fmt.Fprintf(os.Stderr, "Calico CNI IPAM request IP: %v\n", conf.Args.IP)

		// The hostname will be defaulted to the actual hostname if cong.Hostname is empty
		assignArgs := ipam.AssignIPArgs{IP: conf.Args.IP, HandleID: &workloadID, Hostname: conf.Hostname}
		err := ipamClient.AssignIP(assignArgs)
		if err != nil {
			return err
		}

		ipV4Network := net.IPNet{IP: conf.Args.IP, Mask: net.CIDRMask(32, 32)}
		r.IP4 = &types.IPConfig{IP: ipV4Network}
	} else {
		// Default to assigning an IPv4 address
		num4 := 1
		if conf.IPAM.AssignIpv4 != nil && *conf.IPAM.AssignIpv4 == "false" {
			num4 = 0
		}

		// Default to NOT assigning an IPv6 address
		num6 := 0
		if conf.IPAM.AssignIpv6 != nil && *conf.IPAM.AssignIpv6 == "true" {
			num6 = 1
		}

		// TODO - plumb through etcd auth
		assignArgs := ipam.AutoAssignArgs{Num4: num4, Num6: num6, HandleID: &args.ContainerID, Hostname: conf.Hostname}
		assignedV4, assignedV6, err := ipamClient.AutoAssign(assignArgs)
		if err != nil {
			return err
		}

		if num4 == 1 {
			ipV4Network := net.IPNet{IP: assignedV4[0], Mask: net.CIDRMask(32, 32)}
			r.IP4 = &types.IPConfig{IP: ipV4Network}
		}

		if num6 == 1 {
			ipV6Network := net.IPNet{IP: assignedV6[0], Mask: net.CIDRMask(128, 128)}
			r.IP6 = &types.IPConfig{IP: ipV6Network}
		}
	}

	return r.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	// Release the IP address by using the handle - which is workloadID.
	ipamClient, err := ipam.NewIPAMClient()
	if err != nil {
		return err
	}

	workloadID, _, err := utils.GetIdentifiers(args)
	if err != nil {
		return err
	}

	err = ipamClient.ReleaseByHandle(workloadID)
	if err != nil {
		return err
	}

	return nil
}
