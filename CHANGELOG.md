# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Estate standard Rust repository tooling (`rustfmt.toml`, `clippy.toml`, `deny.toml`, `.cargo/config.toml`, `rust-toolchain.toml`, `.github/workflows/ci.yml`, self-documenting `Makefile` and `Justfile`, and `xtask` verification DAG with `graph-audit`, `spec-check`, `toolchain-check`, `branch-hygiene`, DBR queue admission, and `--break-check` mutation self-tests).
- Kubernetes resource quantity (`CpuQuantity`, `MemoryQuantity`, `ResourceQuotaSpec`), RFC 1123 label selector (`LabelSelector`), multi-document YAML manifest (`serde-saphyr`), PodSecurity `restricted` containment (`audit_pod_spec_restricted`, `restricted_pod_security_context`, `restricted_container_security_context`), and Horizon 2 BFT jury quorum & cryptographic execution receipt primitives in `k8-api` with a 100-seed Deterministic Simulation Testing (`DST`) harness.
- Server-Side Apply (`Patch::Apply` with `k8-orchestrator` field manager), dynamic multi-document YAML manifest parsing, status patching, and deadline-aware job reconciliation in `k8-core` and `k8-orchestrator`, plus `k8 crd` and `k8 run --dry-run` CLI manifest emission.

### Changed
- Replaced deprecated `serde_yaml 0.9` (`RUSTSEC-2024-0449` via `unsafe-libyaml`) with safe YAML 1.2 Serde engine `serde-saphyr 0.0.29` (`#![forbid(unsafe_code)]`).

### Fixed

### Removed

### Deprecated

### Security
- Enforced full Kubernetes PodSecurity `restricted` defaults (`runAsNonRoot: true`, UID/GID/fsGroup `65532`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`, `seccompProfile: RuntimeDefault`, `automountServiceAccountToken: false`) and fail-closed spec admission validation before job dispatch.

---
