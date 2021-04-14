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

package main_windows_test

import (
	"encoding/json"
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/cni-plugin/internal/pkg/utils/winpol"
	"github.com/sirupsen/logrus"
)

var mgmtIPNet *net.IPNet
var mgmtIP net.IP

func init() {
	var err error
	mgmtIP, mgmtIPNet, err = net.ParseCIDR("10.11.128.13/19")
	if err != nil {
		panic(err)
	}
	mgmtIPNet.IP = mgmtIP // We want the full IP, not the masked version.
}

var _ = Describe("CalculateEndpointPolicies", func() {
	logger := logrus.WithField("test", "true")

	_, net1, _ := net.ParseCIDR("10.0.1.0/24")
	_, net2, _ := net.ParseCIDR("10.0.2.0/24")

	It("With NAT disabled, OutBoundNAT should be filtered out", func() {
		marshaller := newMockPolMarshaller(
			`{"Type": "OutBoundNAT", "ExceptionList": ["10.96.0.0/12"]}`,
			`{"Type": "SomethingElse"}`,
		)
		pols, _, err := winpol.CalculateEndpointPolicies(marshaller, []*net.IPNet{net1, net2, mgmtIPNet}, false, mgmtIP, logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(pols).To(Equal([]json.RawMessage{
			json.RawMessage(`{"Type": "SomethingElse"}`),
		}), "OutBoundNAT should have been filtered out")

	})

	It("With NAT enabled, OutBoundNAT should be augmented", func() {
		marshaller := newMockPolMarshaller(
			`{"Type": "OutBoundNAT", "ExceptionList": ["10.96.0.0/12"]}`,
			`{"Type": "SomethingElse"}`,
		)
		pols, _, err := winpol.CalculateEndpointPolicies(marshaller, []*net.IPNet{net1, net2, mgmtIPNet}, true, mgmtIP, logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(pols).To(Equal([]json.RawMessage{
			json.RawMessage(`{"ExceptionList":["10.96.0.0/12","10.0.1.0/24","10.0.2.0/24","10.11.128.0/19"],"Type":"OutBoundNAT"}`),
			json.RawMessage(`{"Type": "SomethingElse"}`),
		}))
	})

	It("With NAT enabled, and no OutBoundNAT stanza, OutBoundNAT should be added", func() {
		marshaller := newMockPolMarshaller(
			`{"Type": "SomethingElse"}`,
		)
		pols, _, err := winpol.CalculateEndpointPolicies(marshaller, []*net.IPNet{net1, net2, mgmtIPNet}, true, mgmtIP, logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(pols).To(Equal([]json.RawMessage{
			json.RawMessage(`{"Type": "SomethingElse"}`),
			json.RawMessage(`{"ExceptionList":["10.0.1.0/24","10.0.2.0/24","10.11.128.0/19"],"Type":"OutBoundNAT"}`),
		}))
	})

	It("With NAT disabled, and no OutBoundNAT stanza, OutBoundNAT should not be added", func() {
		marshaller := newMockPolMarshaller(
			`{"Type": "SomethingElse"}`,
		)
		pols, _, err := winpol.CalculateEndpointPolicies(marshaller, []*net.IPNet{net1, net2, mgmtIPNet}, false, mgmtIP, logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(pols).To(Equal([]json.RawMessage{
			json.RawMessage(`{"Type": "SomethingElse"}`),
		}))
	})
})

func newMockPolMarshaller(pols ...string) mockPolMarshaller {
	return mockPolMarshaller(pols)
}

type mockPolMarshaller []string

func (m mockPolMarshaller) MarshalPolicies() (out []json.RawMessage) {
	for _, p := range m {
		out = append(out, json.RawMessage(p))
	}
	return
}