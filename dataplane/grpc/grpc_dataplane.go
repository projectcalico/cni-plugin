// Copyright 2020 Cisco Systems Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grpc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/projectcalico/cni-plugin/dataplane/grpc/proto"
	"github.com/projectcalico/cni-plugin/pkg/types"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

const (
	timeout = 5 * time.Second
)

type grpcDataplane struct {
	socket            string
	allowIPForwarding bool
	mtu               int
	logger            *logrus.Entry
}

func NewGrpcDataplane(conf types.NetConf, logger *logrus.Entry) (*grpcDataplane, error) {
	socket, ok := conf.DataplaneOptions["socket"].(string)
	if !ok {
		return nil, fmt.Errorf("GRPC dataplane socket not configured")
	}
	return &grpcDataplane{
		socket:            socket,
		allowIPForwarding: conf.ContainerSettings.AllowIPForwarding,
		mtu:               conf.MTU,
		logger:            logger,
	}, nil
}

func (d *grpcDataplane) DoNetworking(
	args *skel.CmdArgs,
	result *current.Result,
	desiredVethName string,
	routes []*net.IPNet,
) (ifName, contTapMAC string, err error) {
	d.logger.Infof("Connecting to GRPC backend server at %s", d.socket)
	conn, err := grpc.Dial(d.socket, grpc.WithInsecure())
	if err != nil {
		return "", "", fmt.Errorf("cannot connect to grpc dataplane: %v", err)
	}

	c := proto.NewCniDataplaneClient(conn)

	request := &proto.AddRequest{
		InterfaceName:            args.IfName,
		Netns:                    args.Netns,
		DesiredHostInterfaceName: desiredVethName,
		Settings: &proto.ContainerSettings{
			AllowIpForwarding: d.allowIPForwarding,
			Mtu:               int32(d.mtu),
		},
		ContainerIps:    make([]*proto.IPConfig, 0),
		ContainerRoutes: make([]string, 0),
	}
	for _, ipConf := range result.IPs {
		request.ContainerIps = append(request.ContainerIps, &proto.IPConfig{
			Address: ipConf.Address.String(),
			Gateway: ipConf.Gateway.String(),
		})
	}
	for _, r := range routes {
		request.ContainerRoutes = append(request.ContainerRoutes, r.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	reply, err := c.Add(ctx, request)
	if err != nil {
		d.logger.Errorf("request to grpc dataplane failed : %v", err)
		return "", "", err
	}
	if !reply.GetSuccessful() {
		return reply.GetInterfaceName(), reply.GetContainerMac(), fmt.Errorf("grpc dataplane error: %s", reply.GetErrorMessage())
	}
	return reply.GetInterfaceName(), reply.GetContainerMac(), nil
}

func (d *grpcDataplane) CleanUpNamespace(args *skel.CmdArgs) error {
	d.logger.Infof("Connecting to GRPC backend server at %s", d.socket)
	conn, err := grpc.Dial(d.socket, grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("cannot connect to grpc dataplane: %v", err)
	}
	c := proto.NewCniDataplaneClient(conn)

	request := &proto.DelRequest{
		InterfaceName: args.IfName,
		Netns:         args.Netns,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	reply, err := c.Del(ctx, request)
	if err != nil {
		d.logger.Errorf("request to grpc dataplane failed : %v", err)
		return err
	}
	if !reply.GetSuccessful() {
		return fmt.Errorf("grpc dataplane error: %s", reply.GetErrorMessage())
	}
	return nil
}
