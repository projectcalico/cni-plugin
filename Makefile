.PHONY: all binary test ut clean

SRCFILES=$(shell find calico_rkt)
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | cut -d' ' -f8)


default: all
all: binary test
binary: dist/calico dist/calico-ipam
test: ut


# Builds the Calico CNI plugin binary.
dist/calico: $(SRCFILES) 
	# Make sure the output directory exists.
	mkdir -p dist
	chmod 777 `pwd`/dist

	# Pull the build container.
	docker pull calico/build:latest

	# Build the rkt plugin
	docker run \
	-u user \
	-v `pwd`/dist:/code/dist \
	-v `pwd`/calico_rkt:/code/calico_rkt \
	calico/build pyinstaller calico_rkt/calico_rkt.py -a -F -s --clean

dist/calico-ipam: $(SRCFILES)
	mkdir -p dist
	chmod 777 `pwd`/dist

	# Build the rkt plugin
	docker run \
	-u user \
	-v `pwd`/dist:/code/dist \
	-v `pwd`/calico_rkt:/code/calico_rkt \
	calico/build pyinstaller calico_rkt/ipam.py -a -F -s --clean

# Run the unit tests.
ut: 
	docker run --rm -v `pwd`/calico_rkt:/code/calico_rkt \
	-v `pwd`/calico_rkt/nose.cfg:/code/nose.cfg \
	calico/test \
	nosetests calico_rkt/tests -c nose.cfg


clean:
	-rm -f *.created
	find . -name '*.pyc' -exec rm -f {} +
	-rm -rf dist
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes


## Run etcd in a container. Used by the STs and generally useful.
run-etcd:
	@-docker rm -f calico-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd:v2.2.2 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

