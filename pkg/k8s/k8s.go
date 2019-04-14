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

package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/projectcalico/cni-plugin/pkg/cni_default"
	"net"
	"os"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/projectcalico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/cni-plugin/pkg/types"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	k8sconversion "github.com/projectcalico/libcalico-go/lib/backend/k8s/conversion"
	calicoclient "github.com/projectcalico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// CmdAddK8s performs the "ADD" operation on a kubernetes pod
// Having kubernetes code in its own file avoids polluting the mainline code. It's expected that the kubernetes case will
// more special casing than the mainline code.
func CmdAddK8s(ctx context.Context, args *skel.CmdArgs, conf types.NetConf, epIDs utils.WEPIdentifiers, calicoClient calicoclient.Interface, endpoint *api.WorkloadEndpoint) (*current.Result, error) {
	var err error
	var result *current.Result

	utils.ConfigureLogging(conf.LogLevel)

	logger := logrus.WithFields(logrus.Fields{
		"WorkloadEndpoint": epIDs.WEPName,
		"ContainerID":      epIDs.ContainerID,
		"Pod":              epIDs.Pod,
		"Namespace":        epIDs.Namespace,
	})

	logger.Info("Extracted identifiers for CmdAddK8s")

	// Allocate the IP and update/create the endpoint. Do this even if the endpoint already exists and has an IP
	// allocation. The kubelet will send a DEL call for any old containers and we'll clean up the old IPs then.
	client, err := newK8sClient(conf, logger)
	if err != nil {
		return nil, err
	}
	logger.WithField("client", client).Debug("Created Kubernetes client")

	var routes []*net.IPNet
	if conf.IPAM.Type == "host-local" {
		// We're using the host-local IPAM plugin.  We implement some special-case support for that
		// plugin.  Namely:
		//
		// - We support a special value for its subnet config field, "usePodCIDR".  If that is specified,
		//   we swap the string "usePodCIDR" for the actual PodCIDR (looked up via the k8s API) before we pass the
		//   configuration to the plugin.
		// - We have partial support for its "routes" setting, which allows the routes that we install into
		//   the pod to be varied from our default (which is to insert /0 routes via the host).  If any routes
		//   are specified in the routes section then only the specified routes are programmed.  Since Calico
		//   uses a point-to-point link, the gateway parameter of the route is ignored and the host side IP
		//   of the veth is used instead.
		//
		// We unpack the JSON data as an untyped map rather than using a typed struct because we want to
		// round-trip any fields that we don't know about.
		var stdinData map[string]interface{}
		if err := json.Unmarshal(args.StdinData, &stdinData); err != nil {
			return nil, err
		}

		// Defer to ReplaceHostLocalIPAMPodCIDRs to swap the "usePodCidr" value out.
		var cachedPodCidr string
		getRealPodCIDR := func() (string, error) {
			if cachedPodCidr == "" {
				var err error
				cachedPodCidr, err = getPodCidr(client, conf, epIDs.Node)
				if err != nil {
					return "", err
				}
			}
			return cachedPodCidr, nil
		}
		err = utils.ReplaceHostLocalIPAMPodCIDRs(logger, stdinData, getRealPodCIDR)
		if err != nil {
			return nil, err
		}

		// Write any changes we made back to the input data so that it'll be passed on to the IPAM plugin.
		args.StdinData, err = json.Marshal(stdinData)
		if err != nil {
			return nil, err
		}
		logger.Debug("Updated stdin data")

		// Extract any custom routes from the IPAM configuration.
		ipamData := stdinData["ipam"].(map[string]interface{})
		untypedRoutes := ipamData["routes"]
		hlRoutes, ok := untypedRoutes.([]interface{})
		if untypedRoutes != nil && !ok {
			return nil, fmt.Errorf(
				"failed to parse host-local IPAM routes section; expecting list, not: %v", stdinData["ipam"])
		}
		for _, route := range hlRoutes {
			route := route.(map[string]interface{})
			untypedDst, ok := route["dst"]
			if !ok {
				logger.Debug("Ignoring host-ipam route with no dst")
				continue
			}
			dst, ok := untypedDst.(string)
			if !ok {
				return nil, fmt.Errorf(
					"invalid IPAM routes section; expecting 'dst' to be a string, not: %v", untypedDst)
			}
			_, cidr, err := net.ParseCIDR(dst)
			if err != nil {
				logger.WithError(err).WithField("routeDest", dst).Error(
					"Failed to parse destination of host-local IPAM route in CNI configuration.")
				return nil, err
			}
			routes = append(routes, cidr)
		}
	}

	// Determine which routes to program within the container. If no routes were provided in the CNI config,
	// then use the Calico default routes. If routes were provided then program those instead.
	if len(routes) == 0 {
		logger.Debug("No routes specified in CNI configuration, using defaults.")
		routes = utils.DefaultRoutes
	} else {
		if conf.IncludeDefaultRoutes {
			// We're configured to also include our own default route, so do that here.
			logger.Debug("Including Calico default routes in addition to routes from CNI config")
			routes = append(utils.DefaultRoutes, routes...)
		}
		logger.WithField("routes", routes).Info("Using custom routes from CNI configuration.")
	}

	labels := make(map[string]string)
	annot := make(map[string]string)
	annotNS := make(map[string]string)

	var ports []api.EndpointPort
	var profiles []string
	var generateName string

	// Only attempt to fetch the labels and annotations from Kubernetes
	// if the policy type has been set to "k8s". This allows users to
	// run the plugin under Kubernetes without needing it to access the
	// Kubernetes API
	if conf.Policy.PolicyType == "k8s" {
		var err error

		annotNS, err = getK8sNSInfo(client, epIDs.Namespace)
		if err != nil {
			return nil, err
		}
		logger.WithField("NS Annotations", annotNS).Debug("Fetched K8s namespace annotations")

		labels, annot, ports, profiles, generateName, err = getK8sPodInfo(client, epIDs.Pod, epIDs.Namespace)
		if err != nil {
			return nil, err
		}
		logger.WithField("labels", labels).Debug("Fetched K8s labels")
		logger.WithField("annotations", annot).Debug("Fetched K8s annotations")
		logger.WithField("ports", ports).Debug("Fetched K8s ports")
		logger.WithField("profiles", profiles).Debug("Generated profiles")

		// Check for calico IPAM specific annotations and set them if needed.
		if conf.IPAM.Type == "calico-ipam" {

			var v4pools, v6pools string

			// Sets  the Namespace annotation for IP pools as default
			v4pools = annotNS["cni.projectcalico.org/ipv4pools"]
			v6pools = annotNS["cni.projectcalico.org/ipv6pools"]

			// Gets the POD annotation for IP Pools and overwrites Namespace annotation if it exists
			v4poolpod := annot["cni.projectcalico.org/ipv4pools"]
			if len(v4poolpod) != 0 {
				v4pools = v4poolpod
			}
			v6poolpod := annot["cni.projectcalico.org/ipv6pools"]
			if len(v6poolpod) != 0 {
				v6pools = v6poolpod
			}

			if len(v4pools) != 0 || len(v6pools) != 0 {
				var stdinData map[string]interface{}
				if err := json.Unmarshal(args.StdinData, &stdinData); err != nil {
					return nil, err
				}
				var v4PoolSlice, v6PoolSlice []string

				if len(v4pools) > 0 {
					if err := json.Unmarshal([]byte(v4pools), &v4PoolSlice); err != nil {
						logger.WithField("IPv4Pool", v4pools).Error("Error parsing IPv4 IPPools")
						return nil, err
					}

					if _, ok := stdinData["ipam"].(map[string]interface{}); !ok {
						logger.Fatal("Error asserting stdinData type")
						os.Exit(0)
					}
					stdinData["ipam"].(map[string]interface{})["ipv4_pools"] = v4PoolSlice
					logger.WithField("ipv4_pools", v4pools).Debug("Setting IPv4 Pools")
				}
				if len(v6pools) > 0 {
					if err := json.Unmarshal([]byte(v6pools), &v6PoolSlice); err != nil {
						logger.WithField("IPv6Pool", v6pools).Error("Error parsing IPv6 IPPools")
						return nil, err
					}

					if _, ok := stdinData["ipam"].(map[string]interface{}); !ok {
						logger.Fatal("Error asserting stdinData type")
						os.Exit(0)
					}
					stdinData["ipam"].(map[string]interface{})["ipv6_pools"] = v6PoolSlice
					logger.WithField("ipv6_pools", v6pools).Debug("Setting IPv6 Pools")
				}

				newData, err := json.Marshal(stdinData)
				if err != nil {
					logger.WithField("stdinData", stdinData).Error("Error Marshaling data")
					return nil, err
				}
				args.StdinData = newData
				logger.Debug("Updated stdin data")
			}
		}
	}

	ipAddrsNoIpam := annot["cni.projectcalico.org/ipAddrsNoIpam"]
	ipAddrs := annot["cni.projectcalico.org/ipAddrs"]

	result, err = cni_default.ProcessIpAddrs(ipAddrs, ipAddrsNoIpam, conf, args, logger, calicoClient, endpoint)
	if err != nil {
		return nil, err
	}

	// Configure the endpoint (creating if required).
	if endpoint == nil {
		logger.Debug("Initializing new WorkloadEndpoint resource")
		endpoint = api.NewWorkloadEndpoint()
	}
	endpoint.Name = epIDs.WEPName
	endpoint.Namespace = epIDs.Namespace
	endpoint.Labels = labels
	endpoint.GenerateName = generateName
	endpoint.Spec.Endpoint = epIDs.Endpoint
	endpoint.Spec.Node = epIDs.Node
	endpoint.Spec.Orchestrator = epIDs.Orchestrator
	endpoint.Spec.Pod = epIDs.Pod
	endpoint.Spec.Ports = ports
	endpoint.Spec.IPNetworks = []string{}

	// Set the profileID according to whether Kubernetes policy is required.
	// If it's not, then just use the network name (which is the normal behavior)
	// otherwise use one based on the Kubernetes pod's profile(s).
	if conf.Policy.PolicyType == "k8s" {
		endpoint.Spec.Profiles = profiles
	} else {
		endpoint.Spec.Profiles = []string{conf.Name}
	}

	// Populate the endpoint with the output from the IPAM plugin.
	if err = utils.PopulateEndpointNets(endpoint, result); err != nil {
		// Cleanup IP allocation and return the error.
		utils.ReleaseIPAllocation(logger, conf, args)
		return nil, err
	}
	logger.WithField("endpoint", endpoint).Info("Populated endpoint")
	logger.Infof("Calico CNI using IPs: %s", endpoint.Spec.IPNetworks)

	// releaseIPAM cleans up any IPAM allocations on failure.
	releaseIPAM := func() {
		logger.WithField("endpointIPs", endpoint.Spec.IPNetworks).Info("Releasing IPAM allocation(s) after failure")
		utils.ReleaseIPAllocation(logger, conf, args)
	}

	// Whether the endpoint existed or not, the veth needs (re)creating.
	hostVethName := k8sconversion.VethNameForWorkload(epIDs.Namespace, epIDs.Pod)
	_, contVethMac, err := utils.DoNetworking(args, conf, result, logger, hostVethName, routes)
	if err != nil {
		logger.WithError(err).Error("Error setting up networking")
		releaseIPAM()
		return nil, err
	}

	mac, err := net.ParseMAC(contVethMac)
	if err != nil {
		logger.WithError(err).WithField("mac", mac).Error("Error parsing container MAC")
		releaseIPAM()
		return nil, err
	}
	endpoint.Spec.MAC = mac.String()
	endpoint.Spec.InterfaceName = hostVethName
	endpoint.Spec.ContainerID = epIDs.ContainerID
	logger.WithField("endpoint", endpoint).Info("Added Mac, interface name, and active container ID to endpoint")

	// List of DNAT ipaddrs to map to this workload endpoint
	floatingIPs := annot["cni.projectcalico.org/floatingIPs"]

	if floatingIPs != "" {
		// If floating IPs are defined, but the feature is not enabled, return an error.
		if !conf.FeatureControl.FloatingIPs {
			releaseIPAM()
			return nil, fmt.Errorf("requested feature is not enabled: floating_ips")
		}
		ips, err := cni_default.ParseIPAddrs(floatingIPs, logger)
		if err != nil {
			releaseIPAM()
			return nil, err
		}

		for _, ip := range ips {
			endpoint.Spec.IPNATs = append(endpoint.Spec.IPNATs, api.IPNAT{
				InternalIP: result.IPs[0].Address.IP.String(),
				ExternalIP: ip,
			})
		}
		logger.WithField("endpoint", endpoint).Info("Added floatingIPs to endpoint")
	}

	// Write the endpoint object (either the newly created one, or the updated one)
	if _, err := utils.CreateOrUpdate(ctx, calicoClient, endpoint); err != nil {
		logger.WithError(err).Error("Error creating/updating endpoint in datastore.")
		releaseIPAM()
		return nil, err
	}
	logger.Info("Wrote updated endpoint to datastore")

	// Add the interface created above to the CNI result.
	result.Interfaces = append(result.Interfaces, &current.Interface{
		Name: endpoint.Spec.InterfaceName},
	)

	return result, nil
}

// CmdDelK8s performs CNI DEL processing when running under Kubernetes. In Kubernetes, we identify workload endpoints based on their
// pod name and namespace rather than container ID, so we may receive multiple DEL calls for the same pod, but with different container IDs.
// As such, we must only delete the workload endpoint when the provided CNI_CONATAINERID matches the value on the WorkloadEndpoint. If they do not match,
// it means the DEL is for an old sandbox and the pod is still running. We should still clean up IPAM allocations, since they are identified by the
// container ID rather than the pod name and namespace. If they do match, then we can delete the workload endpoint.
func CmdDelK8s(ctx context.Context, c calicoclient.Interface, epIDs utils.WEPIdentifiers, args *skel.CmdArgs, conf types.NetConf, logger *logrus.Entry) error {
	wep, err := c.WorkloadEndpoints().Get(ctx, epIDs.Namespace, epIDs.WEPName, options.GetOptions{})
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
			// Could not connect to datastore (connection refused, unauthorized, etc.)
			// so we have no way of knowing/checking ContainerID. To protect the endpoint
			// from false DEL, we return the error without deleting/cleaning up.
			return err
		}

		// The WorkloadEndpoint doesn't exist for some reason. We should still try to clean up any IPAM allocations
		// if they exist, so continue DEL processing.
		logger.WithField("WorkloadEndpoint", epIDs.WEPName).Warning("WorkloadEndpoint does not exist in the datastore, moving forward with the clean up")
	} else if wep.Spec.ContainerID != "" && args.ContainerID != wep.Spec.ContainerID {
		// If the ContainerID is populated and doesn't match the CNI_CONATINERID provided for this execution, then
		// we shouldn't delete the workload endpoint. We identify workload endpoints based on pod name and namespace, which means
		// we can receive DEL commands for an old sandbox for a currently running pod. However, we key IPAM allocations based on the
		// CNI_CONTAINERID, so we should still do that below for this case.
		logger.WithField("WorkloadEndpoint", wep).Warning("CNI_CONTAINERID does not match WorkloadEndpoint ConainerID, don't delete WEP.")
	} else if _, err = c.WorkloadEndpoints().Delete(ctx, wep.Namespace, wep.Name, options.DeleteOptions{}); err != nil {
		// Delete the WorkloadEndpoint object from the datastore, passing revision information from the
		// queried resource above in order to prevent conflicts.
		switch err := err.(type) {
		case cerrors.ErrorResourceDoesNotExist:
			// Log and proceed with the clean up if WEP doesn't exist.
			logger.WithField("endpoint", wep).Info("Endpoint object does not exist, no need to clean up.")
		case cerrors.ErrorResourceUpdateConflict:
			// This case means the WEP object was modified between the time we did the Get and now,
			// so it's not a safe Compare-and-Delete operation, so log and abort with the error.
			// Returning an error here is with the assumption that k8s (kubelet) retries deleting again.
			logger.WithField("endpoint", wep).Warning("Error deleting endpoint: endpoint was modified before it could be deleted.")
			return fmt.Errorf("error deleting endpoint: endpoint was modified before it could be deleted: %v", err)
		case cerrors.ErrorOperationNotSupported:
			// KDD does not support WorkloadEndpoint deletion, the WEP is backed by the Pod and the
			// deletion will be handled by Kubernetes. This error can be ignored.
			logger.WithField("endpoint", wep).Info("Endpoint deletion will be handled by Kubernetes deletion of the Pod.")
		default:
			return err
		}
	}

	// Release the IP address for this container by calling the configured IPAM plugin.
	logger.Info("Releasing IP address(es)")
	ipamErr := utils.DeleteIPAM(conf, args, logger)

	// Clean up namespace by removing the interfaces.
	logger.Info("Cleaning up netns")
	err = utils.CleanUpNamespace(args, logger)
	if err != nil {
		return err
	}

	// Return the IPAM error if there was one. The IPAM error will be lost if there was also an error in cleaning up
	// the device or endpoint, but crucially, the user will know the overall operation failed.
	if ipamErr != nil {
		return ipamErr
	}

	logger.Info("Teardown processing complete.")
	return nil
}


func newK8sClient(conf types.NetConf, logger *logrus.Entry) (*kubernetes.Clientset, error) {
	// Some config can be passed in a kubeconfig file
	kubeconfig := conf.Kubernetes.Kubeconfig

	// Config can be overridden by config passed in explicitly in the network config.
	configOverrides := &clientcmd.ConfigOverrides{}

	// If an API root is given, make sure we're using using the name / port rather than
	// the full URL. Earlier versions of the config required the full `/api/v1/` extension,
	// so split that off to ensure compatibility.
	conf.Policy.K8sAPIRoot = strings.Split(conf.Policy.K8sAPIRoot, "/api/")[0]

	var overridesMap = []struct {
		variable *string
		value    string
	}{
		{&configOverrides.ClusterInfo.Server, conf.Policy.K8sAPIRoot},
		{&configOverrides.AuthInfo.ClientCertificate, conf.Policy.K8sClientCertificate},
		{&configOverrides.AuthInfo.ClientKey, conf.Policy.K8sClientKey},
		{&configOverrides.ClusterInfo.CertificateAuthority, conf.Policy.K8sCertificateAuthority},
		{&configOverrides.AuthInfo.Token, conf.Policy.K8sAuthToken},
	}

	// Using the override map above, populate any non-empty values.
	for _, override := range overridesMap {
		if override.value != "" {
			*override.variable = override.value
		}
	}

	// Also allow the K8sAPIRoot to appear under the "kubernetes" block in the network config.
	if conf.Kubernetes.K8sAPIRoot != "" {
		configOverrides.ClusterInfo.Server = conf.Kubernetes.K8sAPIRoot
	}

	// Use the kubernetes client code to load the kubeconfig file and combine it with the overrides.
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
		configOverrides).ClientConfig()
	if err != nil {
		return nil, err
	}

	// Create the clientset
	return kubernetes.NewForConfig(config)
}

func getK8sNSInfo(client *kubernetes.Clientset, podNamespace string) (annotations map[string]string, err error) {
	ns, err := client.CoreV1().Namespaces().Get(podNamespace, metav1.GetOptions{})
	logrus.Infof("namespace info %+v", ns)
	if err != nil {
		return nil, err
	}
	return ns.Annotations, nil
}

func getK8sPodInfo(client *kubernetes.Clientset, podName, podNamespace string) (labels map[string]string, annotations map[string]string, ports []api.EndpointPort, profiles []string, generateName string, err error) {
	pod, err := client.CoreV1().Pods(string(podNamespace)).Get(podName, metav1.GetOptions{})
	logrus.Infof("pod info %+v", pod)
	if err != nil {
		return nil, nil, nil, nil, "", err
	}

	var c k8sconversion.Converter
	kvp, err := c.PodToWorkloadEndpoint(pod)
	if err != nil {
		return nil, nil, nil, nil, "", err
	}

	ports = kvp.Value.(*api.WorkloadEndpoint).Spec.Ports
	labels = kvp.Value.(*api.WorkloadEndpoint).Labels
	profiles = kvp.Value.(*api.WorkloadEndpoint).Spec.Profiles
	generateName = kvp.Value.(*api.WorkloadEndpoint).GenerateName

	return labels, pod.Annotations, ports, profiles, generateName, nil
}

func getPodCidr(client *kubernetes.Clientset, conf types.NetConf, nodename string) (string, error) {
	// Pull the node name out of the config if it's set. Defaults to nodename
	if conf.Kubernetes.NodeName != "" {
		nodename = conf.Kubernetes.NodeName
	}

	node, err := client.CoreV1().Nodes().Get(nodename, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	if node.Spec.PodCIDR == "" {
		return "", fmt.Errorf("no podCidr for node %s", nodename)
	}
	return node.Spec.PodCIDR, nil
}
