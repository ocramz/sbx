# Multi-architecture images: linux/amd64 and linux/arm64

## Context

CI builds, tests and pushes an amd64 image only: the `image` job runs on `ubuntu-24.04`, and `make image` builds for the host's architecture. The Dockerfile already builds both architectures. Its build stage runs on `$BUILDPLATFORM` and cross-compiles a static musl binary for `TARGETARCH` amd64 or arm64. `src/seccomp_layer.rs` has aarch64 code behind `cfg`.

The integration suite cannot run under QEMU: Landlock and seccomp return ENOSYS there. So each architecture is built and tested on a native runner. The repository is public, so `ubuntu-24.04-arm` runners are free; they ship podman, docker, jq, make and Rust.

Goal: `:<sha>`, `:main`, `:<tag>` and `:latest` on ghcr.io become indexes over an amd64 and an arm64 image, each of which passed `make smoke` on its own architecture.

**User decisions:**
- **Images only.** No GitHub Release object, no binaries, no attestations.
- **No version bump.** Multi-arch starts with `:main` once this is merged, and with the next `v*` tag. The published `:v0.3` and `:latest` stay amd64-only until then.

## Design

Each architecture's job pushes its tested image as `:<sha>-<arch>`. On `main` and `v*` tags, a last job joins the two into an index, pushed as `:<sha>` and as each of `PUSH_TAGS`. Every step stays a Makefile target, so CI and local runs are the same commands.

**Makefile**
- `ARCHS ?= amd64 arm64`: the architectures the index joins.
- `ARCH := $(PLATFORM:linux/%=%)`.
- A parse-time check, in the style of the `SMOKE_CGROUP` one: `PLATFORM` must be `linux/amd64` or `linux/arm64`.
- `MANIFEST := localhost/sbx-index:$(VERSION)` is the local name of the list. It differs from `$(IMAGE):$(VERSION)`, so it never collides with the image `make image` built on the same machine.
- `push` pushes this architecture's image only:
  - it checks that the local `$(IMAGE):$(VERSION)` has architecture `$(ARCH)` (`image inspect`), and fails otherwise
  - it tags the image `$(IMAGE):$(VERSION)-$(ARCH)` and pushes that tag
  - it no longer takes `PUSH_TAGS`, so a single-arch image can never overwrite a multi-arch tag
- `manifest` (podman; docker's `manifest` subcommand takes other arguments):
  - creates an empty list, then adds `docker://$(IMAGE):$(VERSION)-<arch>` for each of `ARCHS` with `manifest add`. The explicit transport reads the images from the registry, never from local storage. `manifest add` takes one image in podman 4.9, which the runners have
  - checks that the list's platforms are exactly `ARCHS`
  - pushes it with `--all` as `$(IMAGE):$(VERSION)` and as each of `PUSH_TAGS`, then removes the local list
  - does not pass `--amend`: a list left over from a failed run makes `create` fail instead of merging stale entries

**`.github/workflows/ci.yml`**
- `check` and `image` run on a matrix `{amd64: ubuntu-24.04, arm64: ubuntu-24.04-arm}`. clippy and the unit tests then also compile the aarch64 code.
- `image` keeps its steps (kernel, tag check, `make smoke`, login). Its two push steps become one `make push` on `main` and `v*` tags. `PLATFORM` defaults to the runner's architecture.
- A new `manifest` job:
  - `needs: image`, so it runs only when both architectures passed
  - runs on pushes to `main` and `v*` tags, on `ubuntu-24.04` with `packages: write`
  - logs in as today (podman reads docker's auth file), then runs `make manifest PUSH_TAGS=main`, or `PUSH_TAGS="<tag> latest"` on tags

**Docs**
- README, "Build and test":
  - `make push` and `make manifest` in the command block
  - a sentence saying CI builds and tests each architecture on a native runner
  - the CI paragraph names the published tags
- `CHANGELOG.md`: an `Unreleased` section.
- `docs/implementation.md`: an entry.

No Rust or Dockerfile changes and no new tests: this is build plumbing, not program logic. The safeguards are the architecture check in `push`, the platform check in `manifest`, and a native `make smoke` on both architectures.

## Risks

- **arm64 runner kernel.** It must have Landlock ABI 6 (`TEST_REQUIRE_LANDLOCK=true`) and give podman `--systemd=always` a delegated cgroup (`SMOKE_CGROUP=true`). The amd64 runner (`7.0.0-1017-azure`) passes both. The arm64 runner shows its kernel in the `uname -r` step on its first run.
- **rustup on the arm64 runner.** If `rustup toolchain install` fails there, `check` needs a rustup install step.
- **Status check names.** They become `check (amd64)`, `check (arm64)`, `image (amd64)`, `image (arm64)` and `manifest`. Branch protection that requires `check` or `image` by name must be updated.

## Verification

1. Locally:
   - `make lint test`
   - `make -n push manifest PUSH_TAGS=main`
   - `make smoke` on an arm64 Mac
   - the architecture check fails: `make image PLATFORM=linux/amd64`, then `make push` (host platform)
2. A branch push: both `check` and both `image` jobs pass, and nothing is pushed.
3. After the merge to `main`, the `manifest` job runs:
   - `podman manifest inspect ghcr.io/ocramz/sbx:main` lists amd64 and arm64
   - `sbx version` runs in the image pulled for each platform
4. The next `v*` tag: the tag check passes on both architectures, and `:<tag>` and `:latest` are multi-arch.
