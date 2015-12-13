# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import json
import unittest
from etcd import EtcdException
from mock import patch, MagicMock, call, ANY
from netaddr import IPAddress, IPNetwork
from subprocess32 import CalledProcessError, Popen, PIPE
from nose.tools import assert_equal, assert_true, assert_false, assert_raises
from constants import *

import pycalico.netns
from pycalico.datastore import DatastoreClient
from pycalico.datastore_datatypes import IPPool, Endpoint

import calico_cni 
from calico_cni import CniPlugin
from policy_drivers import DefaultPolicyDriver 


class CniPluginFvTest(unittest.TestCase):
    """
    Performs FV testing on an instance of CniPlugin.

    Mocked out interfaces:
    - subprocess32.Popen
    """
    def setUp(self):
        self.command = None
        self.network_name = "calico-fv"
        self.plugin_type = "calico"
        self.ipam_type = "calico-ipam"
        self.container_id = "ff3afbd1-17ad-499d-b514-72438c009e81"
        self.cni_ifname = "eth0"
        self.cni_args = ""
        self.cni_path = "/usr/bin/rkt/"
        self.cni_netns = "netns"

        # Endpoint created by plugin.
        self.endpoint = None

        # Mock out the datastore client.
        self.client = MagicMock(spec=DatastoreClient)

        # Mock out the policy driver.
        self.policy_driver = MagicMock(spec=DefaultPolicyDriver)

        # Setup module mocks.
        self.popen = calico_cni.Popen
        self.m_popen = MagicMock(spec=self.popen)
        calico_cni.Popen = self.m_popen

        self.os = calico_cni.os
        self.m_os = MagicMock(self.os)
        calico_cni.os = self.m_os

    def tearDown(self):
        # Reset module mocks.
        calico_cni.Popen = self.m_popen
        calico_cni.os = self.os

    def create_plugin(self):
        self.network_config = {
            "name": self.network_name, 
            "type": self.plugin_type,
            "ipam": {
                "type": self.ipam_type,
                "subnet": "10.22.0.0/16",
                "routes": [{"dst": "0.0.0.0/0"}],
                "range-start": "",
                "range-end": ""
            }
        }

        self.env = {
                CNI_CONTAINERID_ENV: self.container_id,
                CNI_IFNAME_ENV: self.cni_ifname,
                CNI_ARGS_ENV: self.cni_args,
                CNI_COMMAND_ENV: CNI_CMD_ADD, 
                CNI_PATH_ENV: self.cni_path, 
                CNI_NETNS_ENV: self.cni_netns
        }

        # Create the CniPlugin to test.
        plugin = CniPlugin(self.network_config, self.env)

        # Mock out policy driver. 
        plugin.policy_driver = self.policy_driver 

        # Mock out the datastore client.
        plugin._client = self.client

        return plugin

    def set_ipam_result(self, stdout, stderr):
        """
        Set the output of the mock IPAM plugin before execution.
        """
        self.m_popen().communicate.return_value = stdout, stderr

    def test_add_mainline(self):
        """
        Tests basic CNI add functionality.
        """
        # Configure.
        self.command = CNI_CMD_ADD
        ip4 = "10.0.0.1/32"
        ipam_stdout = json.dumps({"ip4": {"ip": ip4}, 
                                  "ip6": {"ip": ""}})
        self.set_ipam_result(ipam_stdout, "")

        # Create plugin.
        p = self.create_plugin()

        # Execute.
        rc = p.execute()
        
        # Assert success.
        assert_equal(rc, 0)

        # Assert an endpoint was created.
        self.client.create_endpoint.assert_called_once_with(ANY, 
                "cni", self.container_id, [IPNetwork(ip4)])

        # Assert a profile was applied.
        self.policy_driver.set_profile.assert_called_once_with(self.client.create_endpoint())

    def test_add_error_profile_create(self):
        """
        Tests CNI add, plugin fails to create profile.
        """
        # Configure.
        self.command = CNI_CMD_ADD
        ip4 = "10.0.0.1/32"
        ipam_stdout = json.dumps({"ip4": {"ip": ip4}, 
                                  "ip6": {"ip": ""}})
        self.set_ipam_result(ipam_stdout, "")

        # Create plugin.
        p = self.create_plugin()

        # Configure EtcdException when setting profile.
        p.policy_driver.set_profile = MagicMock(side_effect=EtcdException)

        # Execute.
        rc = p.execute()
        
        # Assert failure.
        assert_equal(rc, 1)

        # Assert an endpoint was created.
        self.client.create_endpoint.assert_called_once_with(ANY, 
                "cni", self.container_id, [IPNetwork(ip4)])

        # Assert set_profile called.
        self.policy_driver.set_profile.assert_called_once_with(self.client.create_endpoint())

        # Assert the endpoint was removed from the datastore.
        self.client.remove_endpoint.assert_called_once_with(ANY, "cni", self.container_id)
