SHELL              := /bin/bash
# go options
GO                 ?= go
GOPATH             ?= $$($(GO) env GOPATH)
DOCKER_CACHE       := $(CURDIR)/.cache
OVS_VERSION        := $(shell head -n 1 build/images/deps/ovs-version)
GO_VERSION         := $(shell head -n 1 build/images/deps/go-version)

USERID  := $(shell id -u)
GRPID   := $(shell id -g)

DOCKER_BUILD_ARGS = --build-arg OVS_VERSION=$(OVS_VERSION)
DOCKER_BUILD_ARGS += --build-arg GO_VERSION=$(GO_VERSION)

all: test

.PHONY: test
test: docker-test-integration

# code linting
.golangci-bin:
	@echo "===> Installing Golangci-lint <==="
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $@ v1.52.2

.PHONY: golangci
golangci: .golangci-bin
	@echo "===> Running golangci <==="
	@GOOS=linux .golangci-bin/golangci-lint run -c .golangci.yml

.PHONY: golangci-fix
golangci-fix: .golangci-bin
	@echo "===> Running golangci-fix <==="
	@GOOS=linux .golangci-bin/golangci-lint run -c .golangci.yml --fix

.PHONY: test-integration
test-integration:
	@echo
	@echo "==> Running integration tests <=="
	@echo "SOME TESTS WILL FAIL IF NOT RUN AS ROOT!"
	$(GO) test antrea.io/ofnet/ofctrl/...

.PHONY: docker-test-integration
docker-test-integration:
	@echo "===> Building Ofnet Test Docker image <==="
ifneq ($(NO_PULL),)
	docker build -t ofnet/test -f build/images/test/Dockerfile $(DOCKER_BUILD_ARGS) .
else
	docker build --pull -t ofnet/test -f build/images/test/Dockerfile $(DOCKER_BUILD_ARGS) .
endif
	@docker run --privileged --rm \
		-e "GOCACHE=/tmp/gocache" \
		-e "GOPATH=/tmp/gopath" \
		-e "INCONTAINER=true" \
		-w /usr/src/antrea.io/ofnet \
		-v $(DOCKER_CACHE)/gopath:/tmp/gopath \
		-v $(DOCKER_CACHE)/gocache:/tmp/gocache \
		-v $(CURDIR):/usr/src/antrea.io/ofnet:ro \
		-v /lib/modules:/lib/modules \
		ofnet/test test-integration $(USERID) $(GRPID)

