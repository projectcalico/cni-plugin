## Calico Networking for rkt 

The CoreOS [documentation](https://github.com/coreos/rkt/blob/master/Documentation/networking.md) for Network Plugins will walk you through the basics of setting up networking in rkt.

## Requirements

* A working [etcd](https://github.com/coreos/etcd) cluster. 
* A build of `calicoctl` after [projectcalico/calico-docker@10460cc405](https://github.com/projectcalico/calico-docker/commit/10460cc405f5aa4bc9ccb1fcaf8760088ae1ebf9)
* Though Calico is capable of networking rkt containers, our core software is distributed and deployed in a [docker container](https://github.com/projectcalico/calico-docker/blob/master/docs/getting-started/default-networking/Demonstration.md). While we work on native rkt support, you will need to run Calico in Docker before starting your rkt containers. This can be easily done wtih `calicoctl` by running the following command: `sudo calicoctl node --ip=<IP> --rkt`

## Installation 


### Install the Plugin
* Running `calicoctl node` with the `--rkt` flag will start the calico/node process and automatically install the plugin for you. Alternatively you can download the [plugin binary](https://github.com/projectcalico/calico-rkt/releases/) yourself and move it to the rkt plugin directory.
```
chmod +x calico_rkt
sudo mv -f ./calico_rkt /usr/lib/rkt/plugins/net/calico
```

### Install Network Configuration Files 

You can configure multiple networks using the CNI.  When using `rkt`, each network is represented by a configuration file in `/etc/rkt/net.d/`.

* Create a network with a `*.conf` file in `/etc/rkt/net.d/`.
    - Each network should be given a unique `"name"`
    - To use Calico networking, specify `"type": "calico"`
    - To use Calico IPAM, specify `"type": "calico-ipam"` in the `"ipam"` section.

For example:
```
~/$ cat /etc/rkt/net.d/10-calico.conf
{
    "name": "example_net",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam",
        "subnet": "10.1.0.0/16"
    }
}
```

## Running containers using Calico
Now that you have installed the Calico CNI plugin and configured a network, just include the `--net=<network_name>` option when starting containers with `rkt`.  The containers will automatically be networked using Project Calico networking.

```
rkt run --net=example_net docker://busybox
```

## Networking Behavior

In rkt deployments, Calico will allocate an available IP within the specified subnet pool and enforce the default Calico networking rules on containers. The default behavior is to allow traffic only from other containers in the network. For each network with a unique `"name"` parameter (as shown above), Calico will create a single profile that will be applied to each container added to that network.

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-rkt/docs/rkt.md?pixel)](https://github.com/igrigorik/ga-beacon)
