// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.
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

// This package contains algorithmic support code for Windows.  I.e. code that is used on
// Windows but can be UTed on any platform.
package winpol

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/sirupsen/logrus"
)

type PolicyMarshaller interface {
	MarshalPolicies() []json.RawMessage
}

// CalculateEndpointPolicies augments the hns.Netconf policies with NAT exceptions for our IPAM blocks.
func CalculateEndpointPolicies(
	n PolicyMarshaller,
	extraNATExceptions []*net.IPNet,
	natOutgoing bool,
	mgmtIP net.IP,
	logger *logrus.Entry,
) ([]json.RawMessage, []hcn.EndpointPolicy, error) {
	inputPols := n.MarshalPolicies()
	var outputV1Pols []json.RawMessage
	var outputV2Pols []hcn.EndpointPolicy

	found := false
	for _, inPol := range inputPols {
		// Decode the raw policy as a dict so we can inspect it without losing any fields.
		decoded := map[string]interface{}{}
		err := json.Unmarshal(inPol, &decoded)
		if err != nil {
			logger.WithError(err).Error("MarshalPolicies() returned bad JSON")
			return nil, nil, err
		}

		// For NAT outgoing, we're looking for an entry like this (we'll add the other IPAM pools to the list):
		//
		// {
		//   "Type":  "OutBoundNAT",
		//   "ExceptionList":  [
		//     "10.96.0.0/12"
		//   ]
		// }
		outPol := inPol
		policyType := decoded["Type"].(string)

		if strings.EqualFold(policyType, "OutBoundNAT") {
			found = true
			if !natOutgoing {
				logger.Info("NAT-outgoing disabled for this IP pool, ignoring OutBoundNAT policy from NetConf.")
				continue
			}

			excList, _ := decoded["ExceptionList"].([]interface{})
			excList = appendCIDRs(excList, extraNATExceptions)
			decoded["ExceptionList"] = excList
			outPol, err = json.Marshal(decoded)
			if err != nil {
				logger.WithError(err).Error("Failed to add outbound NAT exclusion.")
				return nil, nil, err
			}
			logger.WithField("policy", string(outPol)).Debug(
				"Updated OutBoundNAT policy to add Calico IP pools.")
		}

		outputV1Pols = append(outputV1Pols, outPol)

		// Get v2 policy.
		v2Pol, err := convertToHcnEndpointPolicy(decoded)
		if err != nil {
			logger.WithError(err).Error("Failed to convert endpoint policy to HCN endpoint policy.")
			return nil, nil, err
		}
		outputV2Pols = append(outputV2Pols, v2Pol)
	}
	if !found && natOutgoing && len(extraNATExceptions) > 0 {
		exceptions := appendCIDRs(nil, extraNATExceptions)
		dict := map[string]interface{}{
			"Type":          "OutBoundNAT",
			"ExceptionList": exceptions,
		}
		encoded, err := json.Marshal(dict)
		if err != nil {
			logger.WithError(err).Error("Failed to add outbound NAT exclusion.")
			return nil, nil, err
		}

		outputV1Pols = append(outputV1Pols, json.RawMessage(encoded))
		// Get v2 policy.
		v2Pol, err := convertToHcnEndpointPolicy(dict)
		if err != nil {
			logger.WithError(err).Error("Failed to convert endpoint policy to HCN endpoint policy.")
			return nil, nil, err
		}
		outputV2Pols = append(outputV2Pols, v2Pol)
	}

	return outputV1Pols, outputV2Pols, nil
}

// convertToHcnEndpointPolicy converts a map representing the raw data of a V1
// policy and converts it to an HCN endpoint policy.
//
// For example, we convert from raw JSON like:
//
// {
//   "Type":  "OutBoundNAT",
//   "ExceptionList":  [
//     "10.96.0.0/12",
//     "192.168.0.0/16"
//   ]
// }
//
// to:
//
// hcn.EndpointPolicy{
//   Type: hcn.OutBoundNAT,
//   Settings: json.RawMessage(
//     []byte(`{"ExceptionList":["10.96.0.0/12","192.168.0.0/16"]}`),
//   ),
// }
func convertToHcnEndpointPolicy(policy map[string]interface{}) (hcn.EndpointPolicy, error) {
	hcnPolicy := hcn.EndpointPolicy{}

	policyType := policy["Type"].(string)
	// Get v2 policy type.
	v2PolicyType, err := getHcnEndpointPolicyType(policyType)
	if err != nil {
		return hcnPolicy, fmt.Errorf("Invalid endpoint policy type")
	}

	// Remove the Type key from the map, leaving just the policy settings
	// that we marshall.
	delete(policy, "Type")
	policySettings, err := json.Marshal(policy)
	if err != nil {
		return hcnPolicy, fmt.Errorf("Failed to marshal policy settings.")
	}
	hcnPolicy.Type = v2PolicyType
	hcnPolicy.Settings = json.RawMessage(policySettings)
	return hcnPolicy, nil
}

func getHcnEndpointPolicyType(v1Type string) (hcn.EndpointPolicyType, error) {
	switch v1Type {
	case "OutBoundNAT":
		return hcn.OutBoundNAT, nil
	case "ROUTE":
		return hcn.SDNRoute, nil
	case "PA":
		return hcn.NetworkProviderAddress, nil
	case "ACL":
		return hcn.ACL, nil
	case "QOS":
		return hcn.QOS, nil
	case "L2Driver":
		return hcn.L2Driver, nil
	case "L4Proxy":
		return hcn.L4Proxy, nil
	case "PortName":
		return hcn.PortName, nil
	case "EncapOverhead":
		return hcn.EncapOverhead, nil
	case "InterfaceConstraint":
		return hcn.NetworkInterfaceConstraint, nil
	}
	return "", fmt.Errorf("invalid endpoint policy type: %v", v1Type)
}

func appendCIDRs(excList []interface{}, extraNATExceptions []*net.IPNet) []interface{} {
	for _, cidr := range extraNATExceptions {
		maskedCIDR := &net.IPNet{
			IP:   cidr.IP.Mask(cidr.Mask),
			Mask: cidr.Mask,
		}
		excList = append(excList, maskedCIDR.String())
	}
	return excList
}
