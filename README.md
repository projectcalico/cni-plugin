# Calico Networking for CNI

`calico-cni` offers Calico networking as a CNI plugin.

## Building the plugin locally

To build the Calico CNI Plugin locally, clone this repository and run `make`.  This will build the binary, as well as run the unit tests.  To just build the binary, with no tests, run `make binary`.  To only run the unit tests, simply run `make ut`.

## Configuration

Configure your network with a `*.conf` file. 
* The default file location is `/etc/cni/net.d/`. If you choose to put the net configuration file in a different location, be sure to specify the path with the environment variable `CNI_PATH`. 
* Each network should have their own configuration file and must be given a unique `"name"`.
* To call the Calico CNI plugin, set the `"type"` to `"calico"`.
* The `"ipam"` section must include the key `"type": "calico-ipam"` and specify an IP Pool in `"subnet"`. An IP address will be allocated from the indicated `"subnet"` pool.
```
# 10-calico.conf

{
    "name": "example_net",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam",
        "subnet": "10.1.0.0/16"
    }
}
```

## Networking Behavior

Calico will allocate an available IP within the specified subnet pool and enforce the default Calico networking rules on containers. The default behavior is to allow traffic only from other containers in the network. For each network with a unique `"name"` parameter (as shown above), Calico will create a single profile that will be applied to each container added to that network.