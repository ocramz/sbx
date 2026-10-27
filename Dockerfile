# syntax=docker/dockerfile:1.7
#
# Build:   docker build -t sbx .
#          docker build -t sbx-python --build-arg BASE_IMAGE=python:3.13-slim-bookworm .
# Local:   docker run --rm sbx -- /bin/sh -c 'id; cat /etc/hostname'      # 2nd command is denied
#
# Docker's default seccomp profile blocks the landlock_* syscalls on older
# Docker releases; if `sbx probe` says ENOSYS locally, run with
# --security-opt seccomp=unconfined (the platform's outer sandbox still applies).

ARG BASE_IMAGE=debian:bookworm-slim

# ---------------------------------------------------------------- build
FROM rust:1.91-slim-bookworm AS build
ARG TARGETARCH
RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools \
 && rm -rf /var/lib/apt/lists/*
RUN case "${TARGETARCH:-amd64}" in \
      amd64) echo x86_64-unknown-linux-musl ;; \
      arm64) echo aarch64-unknown-linux-musl ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac > /rust-target \
 && rustup target add "$(cat /rust-target)"

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY policy ./policy
# Static binary: no libc dependency, so it can be dropped into any base image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --target "$(cat /rust-target)" \
 && cp "target/$(cat /rust-target)/release/sbx" /sbx

# ---------------------------------------------------------------- runtime
# Any glibc or musl base works: the payload's runtime (python, node, ...)
# comes from here. Pin by digest in production.
FROM ${BASE_IMAGE}

COPY --from=build /sbx /usr/local/bin/sbx
COPY policy/default.toml /etc/sbx/policy.toml
COPY tests/smoke.sh /opt/sbx/smoke.sh

# Scratch dir for the sandboxed uid. On Cloud Run, mount an in-memory volume
# here instead so each instance starts clean.
RUN mkdir -p /workspace && chmod 1777 /workspace

# Deliberately root: sbx is PID 1 and needs root only to drop the payload to
# uid 65534. That uid split is what stops the payload from signalling,
# ptracing or reading /proc of the supervisor on kernels without Landlock
# scoping (ABI < 6). sbx itself never runs payload code.
USER 0:0
WORKDIR /workspace
STOPSIGNAL SIGTERM

# Everything after ENTRYPOINT is overridable per execution
# (Cloud Run: --args; docker: trailing arguments).
ENTRYPOINT ["/usr/local/bin/sbx", "run"]
CMD ["--", "/bin/sh", "-c", "echo 'sbx: no program given, pass e.g. -- python3 /workspace/main.py' >&2; exit 2"]
