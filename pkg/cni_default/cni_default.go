// Copyright 2015 Tigera Inc
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

package cni_default

import (
	"context"
	"errors"
	"fmt"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/projectcalico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/cni-plugin/pkg/types"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	calicoclient "github.com/projectcalico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/sirupsen/logrus"
)

// CmdAddCNIDefault performs the "ADD" operation with default CNI logic

func CmdAddCNIDefault(ctx context.Context, args *skel.CmdArgs, conf types.NetConf, epIDs utils.WEPIdentifiers, calicoClient calicoclient.Interface, endpoint *api.WorkloadEndpoint) (*current.Result, error) {
	var err error
	var result *current.Result

	//// Validate enabled features
	// this is checked is ProcessIpAddrs for both k8s and default versions of plugins

	//if conf.FeatureControl.IPAddrsNoIpam {
	//	return nil, errors.New("requested feature is not supported for this runtime: ip_addrs_no_ipam")
	//}

	logger := logrus.WithFields(logrus.Fields{
		"ContainerID": epIDs.ContainerID,
	})

	// use the CNI network name as the Calico profile.
	profileID := conf.Name

	endpointAlreadyExisted := endpoint != nil
	if endpointAlreadyExisted {
		// There is an existing endpoint - no need to create another.
		// This occurs when adding an existing container to a new CNI network
		// Find the IP address from the endpoint and use that in the response.
		// Don't create the veth or do any networking.
		// Just update the profile on the endpoint. The profile will be created if needed during the
		// profile processing step.
		foundProfile := false
		for _, p := range endpoint.Spec.Profiles {
			if p == profileID {
				logger.Infof("Calico CNI endpoint already has profile: %s\n", profileID)
				foundProfile = true
				break
			}
		}
		if !foundProfile {
			logger.Infof("Calico CNI appending profile: %s\n", profileID)
			endpoint.Spec.Profiles = append(endpoint.Spec.Profiles, profileID)
		}
		result, err = utils.CreateResultFromEndpoint(endpoint)
		logger.WithField("result", result).Debug("Created result from endpoint")
		if err != nil {
			return nil, err
		}
	} else {

		// There's no existing endpoint, so we need to do the following:
		// 1) Call the configured IPAM plugin to get IP address(es)
		// 2) Configure the Calico endpoint
		// 3) Create the veth, configuring it on both the host and container namespace.

		// Parse endpoint labels passed in by Mesos, and store in a map.
		labels := map[string]string{}
		for _, label := range conf.Args.Mesos.NetworkInfo.Labels.Labels {
			// Sanitize mesos labels so that they pass the k8s label validation,
			// as mesos labels accept any unicode value.
			k := utils.SanitizeMesosLabel(label.Key)
			v := utils.SanitizeMesosLabel(label.Value)

			labels[k] = v
		}


		originalLabels := map[string]string{}
		for _, originalLabel := range conf.Args.Mesos.NetworkInfo.Labels.Labels {
			k := originalLabel.Key
			v := originalLabel.Value

			originalLabels[k] = v
		}

		//ipAddrsNoIpam := annot["cni.projectcalico.org/ipAddrsNoIpam"]
		//ipAddrs := annot["cni.projectcalico.org/ipAddrs"]
		ipAddrs := originalLabels["cni.projectcalico.org/ipAddrs"]
		ipAddrsNoIpam := originalLabels["cni.projectcalico.org/ipAddrsNoIpam"]


		logger.Debugf("originalLabels %v, ipAddrs %s, ipAddrsNoIpam %s", originalLabels, ipAddrs, ipAddrsNoIpam)

		result, err = ProcessIpAddrs(ipAddrs, ipAddrsNoIpam, conf, args, logger, calicoClient, endpoint)
		if err != nil {
			return nil, err
		}

		// 1) Run the IPAM plugin and make sure there's an IP address returned.
		// see ProcessIpAddrs switch case ipAddrs == "" && ipAddrsNoIpam == "":


		// 2) Create the endpoint object
		endpoint = api.NewWorkloadEndpoint()
		endpoint.Name = epIDs.WEPName
		endpoint.Namespace = epIDs.Namespace
		endpoint.Spec.Endpoint = epIDs.Endpoint
		endpoint.Spec.Node = epIDs.Node
		endpoint.Spec.Orchestrator = epIDs.Orchestrator
		endpoint.Spec.ContainerID = epIDs.ContainerID
		endpoint.Labels = labels
		endpoint.Spec.Profiles = []string{profileID}

		logger.WithField("endpoint", endpoint).Debug("Populated endpoint (without nets)")
		if err = utils.PopulateEndpointNets(endpoint, result); err != nil {
			// Cleanup IP allocation and return the error.
			utils.ReleaseIPAllocation(logger, conf, args)
			return nil, err
		}
		logger.WithField("endpoint", endpoint).Info("Populated endpoint (with nets)")

		logger.Infof("Calico CNI using IPs: %s", endpoint.Spec.IPNetworks)

		// 3) Set up the veth
		hostVethName, contVethMac, err := utils.DoNetworking(
			args, conf, result, logger, "", utils.DefaultRoutes)
		if err != nil {
			// Cleanup IP allocation and return the error.
			utils.ReleaseIPAllocation(logger, conf, args)
			return nil, err
		}

		logger.WithFields(logrus.Fields{
			"HostVethName":     hostVethName,
			"ContainerVethMac": contVethMac,
		}).Info("Networked namespace")

		endpoint.Spec.MAC = contVethMac
		endpoint.Spec.InterfaceName = hostVethName
	}

	// Write the endpoint object (either the newly created one, or the updated one with a new ProfileIDs).
	if _, err := utils.CreateOrUpdate(ctx, calicoClient, endpoint); err != nil {
		if !endpointAlreadyExisted {
			// Only clean up the IP allocation if this was a new endpoint.  Otherwise,
			// we'd release the IP that is already attached to the existing endpoint.
			utils.ReleaseIPAllocation(logger, conf, args)
		}
		return nil, err
	}

	logger.WithField("endpoint", endpoint).Info("Wrote endpoint to datastore")

	// Add the interface created above to the CNI result.
	result.Interfaces = append(result.Interfaces, &current.Interface{
		Name: endpoint.Spec.InterfaceName},
	)
	return result, nil
}



func ProcessIpAddrs(ipAddrs string, ipAddrsNoIpam string, conf types.NetConf, args *skel.CmdArgs, logger *logrus.Entry, calicoClient calicoclient.Interface, endpoint *api.WorkloadEndpoint) (*current.Result, error){
	var err error
	var result *current.Result

	// Switch based on which annotations are passed or not passed.
	switch {
	case ipAddrs == "" && ipAddrsNoIpam == "":
		// Call the IPAM plugin.
		result, err = utils.AddIPAM(conf, args, logger)
		if err != nil {
			return nil, err
		}

	case ipAddrs != "" && ipAddrsNoIpam != "":
		// Can't have both ipAddrs and ipAddrsNoIpam annotations at the same time.
		e := fmt.Errorf("can't have both annotations: 'ipAddrs' and 'ipAddrsNoIpam' in use at the same time")
		logger.Error(e)
		return nil, e

	case ipAddrsNoIpam != "":
		// Validate that we're allowed to use this feature.
		if conf.IPAM.Type != "calico-ipam" {
			e := fmt.Errorf("ipAddrsNoIpam is not compatible with configured IPAM: %s", conf.IPAM.Type)
			logger.Error(e)
			return nil, e
		}

		if !conf.FeatureControl.IPAddrsNoIpam {
			e := fmt.Errorf("requested feature is not enabled: ip_addrs_no_ipam")
			logger.Error(e)
			return nil, e
		}

		// ipAddrsNoIpam annotation is set so bypass IPAM, and set the IPs manually.
		overriddenResult, err := overrideIPAMResult(ipAddrsNoIpam, logger)
		if err != nil {
			return nil, err
		}
		logger.Debugf("Bypassing IPAM to set the result to: %+v", overriddenResult)

		// Convert overridden IPAM result into current Result.
		// This method fill in all the empty fields necessory for CNI output according to spec.
		result, err = current.NewResultFromResult(overriddenResult)
		if err != nil {
			return nil, err
		}

		if len(result.IPs) == 0 {
			return nil, errors.New("failed to build result")
		}

	case ipAddrs != "":
		// Validate that we're allowed to use this feature.
		if conf.IPAM.Type != "calico-ipam" {
			e := fmt.Errorf("ipAddrs is not compatible with configured IPAM: %s", conf.IPAM.Type)
			logger.Error(e)
			return nil, e
		}

		// If the endpoint already exists, we need to attempt to release the previous IP addresses here
		// since the ADD call will fail when it tries to reallocate the same IPs. releaseIPAddrs assumes
		// that Calico IPAM is in use, which is OK here since only Calico IPAM supports the ipAddrs
		// annotation.
		if endpoint != nil {
			logger.Info("Endpoint already exists and ipAddrs is set. Release any old IPs")
			if err := releaseIPAddrs(endpoint.Spec.IPNetworks, calicoClient, logger); err != nil {
				return nil, fmt.Errorf("failed to release ipAddrs: %s", err)
			}
		}

		// When ipAddrs annotation is set, we call out to the configured IPAM plugin
		// requesting the specific IP addresses included in the annotation.
		result, err = ipAddrsResult(ipAddrs, conf, args, logger)
		if err != nil {
			return nil, err
		}
		logger.Debugf("IPAM result set to: %+v", result)
	}

	return result, nil
}


// CmdDelK8s performs CNI DEL processing when running under Kubernetes. In Kubernetes, we identify workload endpoints based on their
// pod name and namespace rather than container ID, so we may receive multiple DEL calls for the same pod, but with different container IDs.
// As such, we must only delete the workload endpoint when the provided CNI_CONATAINERID matches the value on the WorkloadEndpoint. If they do not match,
// it means the DEL is for an old sandbox and the pod is still running. We should still clean up IPAM allocations, since they are identified by the
// container ID rather than the pod name and namespace. If they do match, then we can delete the workload endpoint.
func CmdDelCNIDefault(ctx context.Context, calicoClient calicoclient.Interface, epIDs utils.WEPIdentifiers, args *skel.CmdArgs, conf types.NetConf, logger *logrus.Entry) error {
	// Release the IP address by calling the configured IPAM plugin.
	ipamErr := utils.DeleteIPAM(conf, args, logger)

	var err error
	// Delete the WorkloadEndpoint object from the datastore.

	if _, err = calicoClient.WorkloadEndpoints().Delete(ctx, epIDs.Namespace, epIDs.WEPName, options.DeleteOptions{}); err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			// Log and proceed with the clean up if WEP doesn't exist.
			logger.WithField("WorkloadEndpoint", epIDs.WEPName).Info("Endpoint object does not exist, no need to clean up.")
		} else {
			return err
		}
	}

	// Clean up namespace by removing the interfaces.
	err = utils.CleanUpNamespace(args, logger)
	if err != nil {
		return err
	}

	// Return the IPAM error if there was one. The IPAM error will be lost if there was also an error in cleaning up
	// the device or endpoint, but crucially, the user will know the overall operation failed.
	return ipamErr
}