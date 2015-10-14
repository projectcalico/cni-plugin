# Calico Networking for CNI

`calico-cni` offers basic Calico networking as a CNI plugin.

## Building the plugin locally

To build the Calico CNI Plugin locally, clone this repository and run `make`.  This will build the binary, as well as run the unit tests.  To just build the binary, with no tests, run `make binary`.  To only run the unit tests, simply run `make ut`.

## Configuration

* Configure your network with a `*.conf` file in `/etc/cni/net.d/`, or if you choose to put the `*.conf` file in a different location, be sure to specify the path with the environment variable `CNI_PATH`. 
    - Each Network should be given a unique `"name"`
    - Each Calico Network config specifies  `"calico"` as `"type"`.
    - The `"ipam"` section must include the key `"type": "calico-ipam"` and specify an IP Pool in `"subnet"`
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
