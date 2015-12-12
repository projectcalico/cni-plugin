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

import socket

# Calico Configuration Constants
ETCD_AUTHORITY_ENV = 'ETCD_AUTHORITY'

# System Specific Constants
ORCHESTRATOR_ID = "rkt"
HOSTNAME = socket.gethostname()
NETNS_ROOT = '/var/lib/rkt/pods/run'

# Constants for accessing environment variables. The following
# set of variables are required by the CNI spec.
CNI_COMMAND_ENV = "CNI_COMMAND"
CNI_CONTAINERID_ENV = "CNI_CONTAINERID"
CNI_NETNS_ENV = "CNI_NETNS"
CNI_IFNAME_ENV = "CNI_IFNAME"
CNI_ARGS_ENV = "CNI_ARGS"
CNI_PATH_ENV = "CNI_PATH"

# CNI Constants
CNI_CMD_ADD = "ADD"
CNI_CMD_DELETE = "DEL"

# CNI Error Codes
ERR_CODE_UNHANDLED = 100
ERR_CODE_FAILED_ASSIGNMENT = 101
ERR_CODE_INVALID_ARGUMENT = 102

# Logging Configuration
LOG_DIR = "/var/log/calico/cni"
