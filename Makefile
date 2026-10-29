# Build, test and publish the sbx image. `make help` lists the targets.
#
# Variables can be overridden on the command line, e.g.
#   make image BASE_IMAGE=python:3.13-slim-bookworm
#   make push VERSION=0123456789ab PUSH_TAGS="main"
#   make smoke DOCKER=docker SMOKE_CGROUP=false

SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DELETE_ON_ERROR:
.SUFFIXES:
MAKEFLAGS += --warn-undefined-variables --no-builtin-rules
.DEFAULT_GOAL := help

# Images default to the host's architecture: under QEMU, x86_64 rustc
# segfaults and Landlock and seccomp return ENOSYS, so `smoke` needs a native
# platform.
HOST_ARCH       := $(patsubst x86_64,amd64,$(patsubst aarch64,arm64,$(shell uname -m)))

REGISTRY        ?= ghcr.io
IMAGE_NAME      ?= ocramz/sbx
VERSION         ?= $(shell git rev-parse --short=12 HEAD)
# What `sbx version` and the report print: the tag on a release commit.
SBX_VERSION     ?= $(shell git describe --tags --always --dirty --match 'v*')
BASE_IMAGE      ?= debian:bookworm-slim
TEST_BASE_IMAGE ?= python:3.13-slim-bookworm
PLATFORM        ?= linux/$(HOST_ARCH)
PUSH_TAGS       ?=
DOCKER          ?= podman
CARGO           ?= cargo
# true: the test container gets a writable cgroup2 (podman --systemd=always)
# and the suite checks cgroup.mode = "delegated"; false (e.g. with Docker):
# it checks that sbx refuses that mode instead.
SMOKE_CGROUP    ?= true

IMAGE        := $(REGISTRY)/$(IMAGE_NAME)
TEST_IMAGE   := $(IMAGE)-test
RUST_VERSION := $(shell sed -n 's/^channel = "\(.*\)"$$/\1/p' rust-toolchain.toml)

ifeq ($(strip $(RUST_VERSION)),)
$(error could not read the toolchain channel from rust-toolchain.toml)
endif
ifeq ($(strip $(VERSION)),)
$(error VERSION is empty: run inside the git checkout or pass VERSION=...)
endif
ifeq ($(strip $(SBX_VERSION)),)
$(error SBX_VERSION is empty: run inside the git checkout or pass SBX_VERSION=...)
endif
ifeq ($(filter $(SMOKE_CGROUP),true false),)
$(error SMOKE_CGROUP must be true or false)
endif
# Compiled into sbx (cargo build, test, clippy).
export SBX_VERSION

DOCKER_BUILD = $(DOCKER) build --platform $(PLATFORM) \
	--build-arg RUST_VERSION=$(RUST_VERSION) \
	--build-arg SBX_VERSION=$(SBX_VERSION) \
	--label org.opencontainers.image.revision=$(VERSION) \
	--label org.opencontainers.image.version=$(SBX_VERSION)

.PHONY: help
help: ## list the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-12s %s\n", $$1, $$2}'

.PHONY: build
build: ## release build of sbx for this host
	$(CARGO) build --release --locked

.PHONY: fmt
fmt: ## format the code
	$(CARGO) fmt

.PHONY: lint
lint: ## rustfmt check and clippy (warnings are errors)
	$(CARGO) fmt --check
	$(CARGO) clippy --locked --all-targets -- -D warnings

.PHONY: test
test: ## unit tests
	$(CARGO) test --locked

.PHONY: smoke-local
smoke-local: build ## integration suite on this host (needs root; isolated in a mount namespace)
	tests/run-local.sh target/release/sbx

.PHONY: image
image: ## build the runtime image $(IMAGE):$(VERSION) on BASE_IMAGE
	$(DOCKER_BUILD) --target runtime --build-arg BASE_IMAGE=$(BASE_IMAGE) -t $(IMAGE):$(VERSION) .

.PHONY: test-image
test-image: ## build the test image (runtime stage on TEST_BASE_IMAGE plus the suite)
	$(DOCKER_BUILD) --target test --build-arg BASE_IMAGE=$(TEST_BASE_IMAGE) -t $(TEST_IMAGE):$(VERSION) .

.PHONY: smoke
smoke: image test-image ## integration suite in the test image, then checks of the runtime image
	$(DOCKER) run --rm --pull=never --platform $(PLATFORM) --cap-add SYS_PTRACE \
		$(if $(filter true,$(SMOKE_CGROUP)),--systemd=always) \
		--tmpfs /mnt/sbx-vol:rw,mode=0755 \
		-e SBX=/usr/local/bin/sbx -e TEST_VOLUME=/mnt/sbx-vol -e TEST_REQUIRE_IPV6=true -e TEST_REQUIRE_LANDLOCK=true \
		-e TEST_REQUIRE_CGROUP=$(SMOKE_CGROUP) \
		--entrypoint python3 $(TEST_IMAGE):$(VERSION) /opt/sbx/tests/smoke.py
	DOCKER="$(DOCKER)" PLATFORM="$(PLATFORM)" SBX_VERSION="$(SBX_VERSION)" tests/image-checks.sh $(IMAGE):$(VERSION)

.PHONY: probe
probe: ## run `sbx probe` with the default policy in the runtime image
	$(DOCKER) run --rm --pull=never --platform $(PLATFORM) --entrypoint /usr/local/bin/sbx $(IMAGE):$(VERSION) probe

.PHONY: push
push: ## push $(IMAGE):$(VERSION), then tag and push each of PUSH_TAGS
	$(DOCKER) push $(IMAGE):$(VERSION)
	for tag in $(PUSH_TAGS); do \
		$(DOCKER) tag $(IMAGE):$(VERSION) $(IMAGE):$$tag; \
		$(DOCKER) push $(IMAGE):$$tag; \
	done

.PHONY: live
live: ## live tests on a Cloud Run service and jobs: build, push, deploy, run the tests, logs (README)
	tests/cloud-run.sh all

.PHONY: live-down
live-down: ## delete the live tests' Cloud Run service, jobs and image repository
	tests/cloud-run.sh down

.PHONY: ci
ci: lint test smoke ## everything CI runs before pushing

# `make print-VAR` prints a variable, e.g. for tests/cloud-run.sh.
print-%:
	@echo '$($*)'

.PHONY: clean
clean: ## remove build outputs
	$(CARGO) clean
