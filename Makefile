GO_PACKAGER_DOCKER_IMAGE="quay.io/mullvad/go-packager@sha256:7cd9d52c13f70b0b95e312609e3321bbc61e3e2f3478f5e30f7df194289a9ebb"
DOCKER_TEST_IMAGE=wg-manager-testing

# Use pwd command instead of env to support running sudo make for those that do not have
# docker setup to be run as non-root user.
PWD=${shell pwd}

.PHONY: ci clean fmt install integration-test package setup-testing-environment shell test vet

all: test vet install

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test -short ./...

integration-test:
	go test -v ./...

docker-test: .make/docker_local_testing
	docker run --rm -it --cap-add CAP_NET_ADMIN,CAP_NET_RAW -v ${PWD}:/repo ${DOCKER_TEST_IMAGE} bash -c "./setup_testing_environment.sh; gotestsum --format standard-verbose; gotestsum --format standard-verbose --watch"

ci: vet test
	sudo ./setup_testing_environment.sh
	go test -c ./portforward && go test -c ./wireguard
	sudo ./portforward.test -test.v
	sudo ./wireguard.test -test.v

install:
	go install ./...

package:
	docker run --rm -v ${PWD}:/repo -v ${PWD}/build:/build ${GO_PACKAGER_DOCKER_IMAGE}

shell: .make/docker_local_testing
	docker run --rm -it --cap-add CAP_NET_ADMIN,CAP_NET_RAW -p 8000:8000 -v ${PWD}:/repo ${DOCKER_TEST_IMAGE} bash

clean:
	rm -rf build .make wg-manager
	docker image rm ${DOCKER_TEST_IMAGE}

# Helper targets

.make:
	mkdir -p .make

.make/docker_local_testing: Dockerfile.local_testing .make
	docker build -t ${DOCKER_TEST_IMAGE} --build-arg base_image=${GO_PACKAGER_DOCKER_IMAGE} -f $< .
	touch $@
