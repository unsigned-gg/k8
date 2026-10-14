# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Estate standard Rust repository tooling (`rustfmt.toml`, `clippy.toml`, `deny.toml`, `.cargo/config.toml`, `rust-toolchain.toml`, `.github/workflows/ci.yml`, self-documenting `Makefile` and `Justfile`, and `xtask` verification DAG with `graph-audit`, `spec-check`, `toolchain-check`, `branch-hygiene`, DBR queue admission, and `--break-check` mutation self-tests).
- Kubernetes resource quantity (`CpuQuantity`, `MemoryQuantity`, `ResourceQuotaSpec`), RFC 1123 label selector (`LabelSelector`), multi-document YAML manifest (`serde-saphyr`), PodSecurity `restricted` containment (`audit_pod_spec_restricted`, `restricted_pod_security_context`, `restricted_container_security_context`), and Horizon 2 BFT jury quorum & cryptographic execution receipt primitives in `k8-api` with a 100-seed Deterministic Simulation Testing (`DST`) harness.
- Server-Side Apply (`Patch::Apply` with `k8-orchestrator` field manager), dynamic multi-document YAML manifest parsing, status patching, and deadline-aware job reconciliation in `k8-core` and `k8-orchestrator`, plus `k8 crd` and `k8 run --dry-run` CLI manifest emission.
- Wave-1 Kubernetes lifecycle (`controller_owner_reference`, `FINALIZER_WORKLOAD_CLEANUP` state machine, monotonic `upsert_condition` transition algebra), zero-trust `NetworkPolicy` synthesis and fail-closed CIDR egress auditing (`build_isolated_network_policy`, `validate_non_wildcard_cidr`, `audit_network_policy_zero_trust`), Kata microVM `IsolationProfile` (`runtimeClassName: "kata"`), GPU & agent-pool `Toleration`s, `TopologySpreadConstraint`s, and `PodDisruptionBudget` builders in `k8-api` (`SPEC-0002`).
- Pure zero-I/O `AgentWorkload` controller state machine (`reconcile_workload_pure`, `ReconcileObservation`, `ReconcileEffect`, `ReconcilePlan`), Server-Side Apply execution (`Orchestrator::execute_reconcile_plan`), multi-document YAML 1.2 workload bundle rendering (`Orchestrator::render_workload_bundle_yaml`), and `k8 audit -f` / `k8 run --kata --allow-cidr --allow-port --bundle` CLI flags.
- Wave-2 least-privilege RBAC primitives (`build_dedicated_service_account`, `audit_service_account_zero_trust`, `ScopedRuleSpec`, `build_scoped_role`, `build_scoped_role_binding`, `audit_role_least_privilege`), Kata-aware namespace `ResourceQuota` & `LimitRange` headroom governance (`NamespaceQuotaSpec`, `evaluate_quota_admission`, `DEFAULT_KATA_MEMORY_OVERHEAD_BYTES = 256Mi`), bounded ephemeral scratch volumes (`ScratchVolumeSpec`, `build_scratch_volume_and_mount`, `audit_pod_volumes`), and pure multi-gate `ValidatingAdmissionPolicy` engine (`evaluate_workload_admission` with deterministic 64-bit FNV-1a `decision_digest`) in `k8-api` (`SPEC-0003`), plus `k8 admit -f` and `k8 run --scratch-tmp` CLI support.

### Changed
- Replaced deprecated `serde_yaml 0.9` (`RUSTSEC-2024-0449` via `unsafe-libyaml`) with safe YAML 1.2 Serde engine `serde-saphyr 0.0.29` (`#![forbid(unsafe_code)]`).

### Fixed

### Removed

### Deprecated

### Security
- Enforced full Kubernetes PodSecurity `restricted` defaults (`runAsNonRoot: true`, UID/GID/fsGroup `65532`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`, `seccompProfile: RuntimeDefault`, `automountServiceAccountToken: false`) and fail-closed spec admission validation before job dispatch.
- Enforced default-deny inbound and non-wildcard CIDR outbound `NetworkPolicy` isolation (`0.0.0.0/0` and `::/0` rejected fail-closed) alongside optional Kata microVM hardware isolation (`runtimeClassName: "kata"`).
- Enforced least-privilege per-workload `ServiceAccount`/`Role` scoping (rejecting `*` wildcards, escalation/mutating verbs, and unscoped `secrets` access) and bounded `emptyDir` scratch volume auditing (rejecting `hostPath`, unbounded `emptyDir`, and sensitive `/proc`, `/sys`, `/dev`, `/var/run` mount paths).

---

