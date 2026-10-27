# syntax=docker/dockerfile:1.7
#
# Built through the Makefile, which passes every build argument:
#   make image       runtime image on BASE_IMAGE
#   make test-image  runtime stage on a Python base, plus the integration suite
# There are deliberately no defaults: a missing build argument fails the build.

ARG RUST_VERSION
ARG BASE_IMAGE

# ---------------------------------------------------------------- build
# Runs on the build machine's own architecture and cross-compiles for the
# target, since x86_64 rustc segfaults under QEMU (amd64 images on arm64 Macs,
# for Cloud Run). The musl targets link with rust-lld and Rust's bundled musl,
# so no C cross toolchain is needed.
FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-slim-bookworm AS build
ARG TARGETARCH
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
RUN case "${TARGETARCH}" in \
      amd64) echo x86_64-unknown-linux-musl ;; \
      arm64) echo aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH '${TARGETARCH}'" >&2; exit 1 ;; \
    esac > /rust-target \
 && rustup target add "$(cat /rust-target)"

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# Static binary (the musl target is self-contained and every dependency is
# pure Rust), so it can be dropped into any base image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --target "$(cat /rust-target)" \
 && cp "target/$(cat /rust-target)/release/sbx" /sbx
RUN if readelf -lW /sbx | grep -q INTERP; then echo "sbx is not statically linked" >&2; exit 1; fi

# ---------------------------------------------------------------- runtime
# The payload's runtime (python, node, ...) comes from BASE_IMAGE. Pin it by
# digest in production.
FROM ${BASE_IMAGE} AS runtime
LABEL org.opencontainers.image.source="https://github.com/ocramz/sbx" \
      org.opencontainers.image.description="Landlock + seccomp sandbox launcher for untrusted programs" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /sbx /usr/local/bin/sbx
COPY policy/default.toml /etc/sbx/policy.toml
COPY policy/egress.example.toml /etc/sbx/egress.example.toml
COPY policy/no-landlock.example.toml /etc/sbx/no-landlock.example.toml
ENV SBX_POLICY_FILE=/etc/sbx/policy.toml

# Scratch dir for the sandboxed uid. On Cloud Run, mount an in-memory volume
# here instead so each instance starts clean.
RUN mkdir -p /workspace && chmod 1777 /workspace

# The shipped policies must match this image: a missing or symlinked path in
# a rule fails the build here instead of at run time.
RUN ["/usr/local/bin/sbx", "policy", "--quiet"]
RUN ["/usr/local/bin/sbx", "policy", "--quiet", "--policy", "/etc/sbx/egress.example.toml"]
RUN ["/usr/local/bin/sbx", "policy", "--quiet", "--policy", "/etc/sbx/no-landlock.example.toml"]

# Deliberately root: sbx is PID 1 and needs root only to drop the program to
# uid 65534 and empty its capability sets. sbx itself never runs payload code.
USER 0:0
WORKDIR /workspace
STOPSIGNAL SIGTERM

# Everything after ENTRYPOINT is overridable per execution
# (Cloud Run: --args; docker: trailing arguments).
ENTRYPOINT ["/usr/local/bin/sbx", "run"]
CMD ["--", "/bin/sh", "-c", "echo 'sbx: no program given; pass e.g. -- python3 /workspace/main.py' >&2; exit 2"]

# ---------------------------------------------------------------- test
# Runtime stage built on a Python base (BASE_IMAGE=python:...), plus the suites
# and the HTTP front that runs them on a Cloud Run service (tests/cloud-run.sh).
FROM runtime AS test
COPY tests/smoke.py tests/live.py tests/live_server.py /opt/sbx/tests/
