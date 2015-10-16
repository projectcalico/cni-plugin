.PHONY: all binary ut clean

BUILD_FILES=Dockerfile requirements.txt

default: all
all: test
binary: dist/calico_cni
test: ut

# Build a new docker image to be used by binary or tests
cnibuild.created: $(BUILD_FILES)
	docker build -t calico/cni-build .
	touch cnibuild.created

dist/calico_cni: cnibuild.created
	mkdir -p dist
	chmod 777 `pwd`/dist
	
	# Build the cni plugin
	docker run \
	-u user \
	-v `pwd`/calico_cni:/code/calico_cni \
	-v `pwd`/dist:/code/dist \
	-e PYTHONPATH=/code/calico_cni \
	calico/cni-build pyinstaller calico_cni/calico_cni.py -a -F -s --clean

ut: dist/calico_cni
	docker run --rm -v `pwd`/calico_cni:/code/calico_cni \
	-v `pwd`/nose.cfg:/code/nose.cfg \
	calico/cni-build bash -c \
	'>/dev/null 2>&1 & PYTHONPATH=/code/calico_cni \
	nosetests calico_cni/tests -c nose.cfg'

clean:
	-rm -f *.created
	find . -name '*.pyc' -exec rm -f {} +
	-rm -rf dist
	-docker rm -f calico-build
	-docker rmi calico/cni-build
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes

