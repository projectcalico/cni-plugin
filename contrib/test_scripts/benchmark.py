import json
import os
import random
import string
from subprocess import check_call

import sys
from time import time


def test():
    container_id = ''.join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    netnspath = "/var/run/netns/" + container_id
    check_call("ip netns add " + container_id, shell=True)
    check_call("ip netns exec %s ip link set lo up " % container_id, shell=True)

    os.environ.update({"CNI_COMMAND": "ADD",
           "CNI_CONTAINERID": container_id,
           "CNI_NETNS": netnspath,
           "CNI_IFNAME": "eth0",
           "CNI_PATH": "/home/tom/go/src/github.com/appc/cni/bin/"})

    plugin = ""
    with open(sys.argv[1], 'r') as f:
        data = json.load(f)
        plugin = data["type"]
    with open(sys.argv[1], 'r') as f:
        check_call("command time -o addstats -a -f '%e,%S,%U,%M,%t,%K,%I,%O' " + plugin, stdin=f, env=os.environ, shell=True)
#    check_call("ip netns exec %s ifconfig eth0" % container_id, shell=True)
    check_call("ip netns exec %s ip route" % container_id, shell=True)
#    check_call("ifconfig cali%s || true" % container_id, shell=True)
#    check_call("etcdctl ls /calico/v1/host/gulfstream/workload/cni/%s --recursive |tail -1 | xargs etcdctl get" % container_id, shell=True)
    os.environ["CNI_COMMAND"] = "DEL"
    with open(sys.argv[1], 'r') as f:
        check_call("command time -o delstats -a -f '%e,%S,%U,%M,%t,%K,%I,%O' " + plugin, stdin=f, env=os.environ, shell=True)
    check_call("ip netns delete %s" % container_id, shell=True)


reps = 10

check_call("rm -f addstats delstats", shell=True)
for i in range(0, reps):
    test()

print "Add stats"
print "wallclock(s),system(s),user(s),max rss(KB),avg rss(KB),avg tot mem(KB),I,O"
check_call("cat addstats", shell=True)

print "\nDel stats"
print "wallclock(s),system(s),user(s),max rss(KB),avg rss(KB),avg tot mem(KB),I,O"
check_call("cat delstats", shell=True)
