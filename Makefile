GO_PACKAGER_DOCKER_IMAGE="quay.io/mullvad/go-packager@sha256:7cd9d52c13f70b0b95e312609e3321bbc61e3e2f3478f5e30f7df194289a9ebb"

.PHONY: ci clean fmt install integration-test package shell test vet
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
	docker run --rm -it --cap-add CAP_NET_ADMIN -v ${PWD}:/repo wg-manager-testing bash -c "./setup_testing_environment.sh; gotestsum; gotestsum --watch"

ci: integration-test vet

install:
	go install ./...

package:
	docker run --rm -v ${PWD}:/repo -v ${PWD}/build:/build ${GO_PACKAGER_DOCKER_IMAGE}

shell: .make/docker_local_testing
	docker run --rm -it --cap-add CAP_NET_ADMIN -v ${PWD}:/repo wg-manager-testing bash

clean:
	rm -r build .make wg-manager

# Helper targets

.make:
	mkdir -p .make

.make/docker_local_testing: Dockerfile.local_testing .make
	docker build -t wg-manager-testing --build-arg base_image=${GO_PACKAGER_DOCKER_IMAGE} -f $< .
	touch $@
