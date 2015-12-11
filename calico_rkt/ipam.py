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

import logging
import json
import os
import sys

from pycalico.ipam import IPAMClient
from util import configure_logging

LOG_FILENAME = "ipam.log"

_log = logging.getLogger(__name__)
datastore_client = IPAMClient()

# Error codes
ERR_CODE_UNHANDLED = 100
ERR_CODE_FAILED_ASSIGNMENT = 101
ERR_CODE_INVALID_ARGUMENT = 102


class IpamPlugin(object):
    def __init__(self, config, environment):
        self.config = config
        """
        Dictionary representation of the config passed via stdin.
        """

        self.env = environment
        """
        Current environment (e.g os.environ)
        """

        self.command = None
        """
        Command indicating which action to take - one of "ADD" or "DEL".
        """

        self.container_id = None
        """
        Identifier for the container for which we are performing IPAM.
        """

        # Validate the given config and environment and set fields
        # using the given config and environment.
        self._parse_config()

    def calico_ipam(self):
        """
        Assigns or un-assigns IP addresses for the specified container.
        :return:
        """
        if self.command == "ADD":
            # Assign an IP address for this container.
            _log.info("Assigning address to container %s", self.container_id)
            ipv4, ipv6 = self._assign_address(handle_id=self.container_id)
    
            # Output the response and exit successfully.
            print json.dumps({"ip4": {"ip": str(ipv4),},"ip6": {"ip": str(ipv6),},})
        else:
            # Un-assign any IP addresses for this container.
            assert self.command == "DEL", "Invalid command: %s" % self.command
    
            # Release IPs using the container_id as the handle.
            _log.info("Un-assigning address on container %s", self.container_id)
            try:
                datastore_client.release_ip_by_handle(handle_id=self.container_id)
            except KeyError:
                _log.warning("No IPs assigned to container_id %s", self.container_id)

    def _assign_address(self, handle_id, ipv4_pool=None, ipv6_pool=None):
        """
        Assigns an IPv4 and IPv6 address within the given pools.  If no pools are given,
        they will be automatically chosen.
    
        :return: A tuple of (IPv4, IPv6) address assigned.
        """
        ipv4 = None
        ipv6 = None
        try:
            ipv4_addrs, ipv6_addrs = datastore_client.auto_assign_ips(num_v4=1,
                                                                      num_v6=0,
                                                                      handle_id=handle_id,
                                                                      attributes=None,
                                                                      pool=(ipv4_pool, ipv6_pool))
            ipv4 = ipv4_addrs[0]
        except RuntimeError as err:
            _log.error("Cannot auto assign IPAddress: %s", err.message)
            _exit_on_error(code=ERR_CODE_FAILED_ASSIGNMENT,
                           message="Failed to assign IP address",
                           details=err.message)
        else:
            _log.info("Assigned IPv4: %s, IPv6: %s", ipv4, ipv6)
            return ipv4, ipv6

    def _parse_config(self):
        """
        Validates that the plugins environment and given config contain the required
        values.
        """
        _log.debug('Environment: %s', self.env)
        _log.debug('Config: %s', self.config)
    
        # Check the given environment contains the required fields.
        try:
            self.command = env['CNI_COMMAND']
        except KeyError:
            _exit_on_error(code=ERR_CODE_INVALID_ARGUMENT,
                           message="Arguments Invalid",
                           details="CNI_COMMAND not found in environment")
        else:
            # If the command is present, make sure it is valid.
            if self.command not in ["ADD", "DEL"]:
                _exit_on_error(code=ERR_CODE_INVALID_ARGUMENT,
                               message="Arguments Invalid",
                               details="Invalid command '%s'" % self.command)

        try:
            self.container_id = env['CNI_CONTAINERID']
        except KeyError:
            _exit_on_error(code=ERR_CODE_INVALID_ARGUMENT,
                           message="Arguments Invalid",
                           details="CNI_CONTAINERID not found in environment")


def _exit_on_error(code, message, details=""):
    """
    Return failure information to the calling plugin as specified in the CNI spec and exit.
    :param code: Error code to return (int)
    :param message: Short error message to return.
    :param details: Detailed error message to return.
    :return:
    """
    _log.error("Exiting with: `%s: %s`", message, details)
    print json.dumps({"code": code, "message": message, "details": details})
    sys.exit(code)


if __name__ == '__main__':
    # Setup logger
    configure_logging(_log, LOG_FILENAME)

    # Get copy of environment.
    env = os.environ.copy()

    # Read config file from stdin.
    _log.info("Reading config from stdin")
    conf_raw = ''.join(sys.stdin.readlines()).replace('\n', '')
    config = json.loads(conf_raw)

    # Create plugin instance.
    plugin = IpamPlugin(config, env)

    try:
        # Execute IPAM.
        plugin.calico_ipam()
    except Exception, e:
        _log.exception("Unhandled exception")
        _exit_on_error(ERR_CODE_UNHANDLED,
              message="Unhandled Exception",
              details=e.message)
