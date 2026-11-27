# Split the README into an introduction and topic docs

## Why

The README is about 500 lines of reference: mechanism tables, the architecture, every report key, the series' memory bound, Cloud Run findings, the live tests' IAM setup. A new reader cannot find what sbx is, what running it looks like, or how to set it up on their platform.

## What

- **README.md**: a one-line pitch, an example with its real output, what sbx enforces (one line each, linked), setup recipes for typical scenarios (own image, egress, batch jobs, a server that spawns sbx, Cloud Run, gVisor, checking before deploying), limits, a documentation index, building from source.
- **docs/**, one file per topic. The README's text moves there word for word; only links change, and a few subheadings are added.

| File | README sections |
|---|---|
| `docs/how-it-works.md` | the introduction's details, Requirements → mechanism, Architecture, The layers, Threat model and limitations |
| `docs/configuration.md` | Configuration, split under subheadings (policy file, upgrading, flags and variables, commands, exit codes), Kernel and container requirements |
| `docs/egress.md` | Egress filtering |
| `docs/report.md` | Job report and log file, Memory by kind, Time series |
| `docs/cgroup.md` | cgroup limits |
| `docs/platforms.md` | Without Landlock, Without the listener, Deploying on Cloud Run |
| `docs/development.md` | Build and test, CI, the `make gvisor` paragraph, Live tests on Cloud Run, Files |

- Links: `#anchor` becomes `file.md#anchor` across files; repository paths get `../`.
- References to README sections elsewhere point at the new files: CHANGELOG links, `src/cgroup.rs` error messages, `src/policy.rs` comments, the policy files' comments, the Makefile's help, `tests/cloud-run.sh`.

## Checks

- Every sentence of the old README is in the new README or docs (a script, link targets ignored), apart from the rewritten introduction.
- Every relative link and anchor in README.md, docs/*.md and CHANGELOG.md resolves.
- The README's example output is captured from a real run; the own-image Dockerfile builds and runs; the egress recipe runs.
- `make lint test`.
