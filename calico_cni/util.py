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
import logging
from constants import LOG_DIR

# Define log formt.
LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"


def configure_logging(logger, log_filename, log_dir=LOG_DIR, log_level=logging.DEBUG):
    """Configures logging for given logger using the given filename.

    :return None.
    """
    # If the logging directory doesn't exist, create it.
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_path = os.path.join(log_dir, log_filename)

    # Create a log handler and formtter and apply to _log.
    hdlr = logging.FileHandler(filename=log_path)
    formatter = logging.Formatter(LOG_FORMAT)
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(log_level)

    # Attach a stderr handler to the log.
    stderr_hdlr = logging.StreamHandler(sys.stderr)
    stderr_hdlr.setLevel(logging.INFO)
    stderr_hdlr.setFormatter(formatter)
    logger.addHandler(stderr_hdlr)
    

def _log_interfaces(namespace):
    """
    Log interface state in namespace and default namespace.

    :param namespace
    :type namespace str
    """
    try:
        if _log.isEnabledFor(logging.DEBUG):
            interfaces = check_output(['ip', 'addr'])
            _log.debug("Interfaces in default namespace:\n%s", interfaces)

            namespaces = check_output(['ip', 'netns', 'list'])
            _log.debug("Namespaces:\n%s", namespaces)

            cmd = ['ip', 'netns', 'exec', str(namespace), 'ip', 'addr']
            namespace_interfaces = check_output(cmd)

            _log.debug("Interfaces in namespace %s:\n%s",
                         namespace, namespace_interfaces)
    except BaseException:
        # Don't exit if we hit an error logging out the interfaces.
        _log.exception("Ignoring error logging interfaces")


# Set up logger for util.py
LOG_FILENAME = "cni.log"
_log = logging.getLogger(__name__)
configure_logging(_log, LOG_FILENAME)
