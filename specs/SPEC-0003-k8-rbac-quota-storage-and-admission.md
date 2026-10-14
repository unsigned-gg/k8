---
status: Active
created: 2026-10-14
author: Forseti
---

# SPEC-0003: Least-Privilege RBAC, Namespace Quota Governance, Volume Hygiene, and Pure Admission Engine

## Context

Wave-0 (`SPEC-0001`) established resource quantities, label selectors, Pod Security Standards (`Restricted`) contexts, safe YAML 1.2 serialization (`serde-saphyr`), and BLAKE3 jury receipts. Wave-1 (`SPEC-0002`) added controller `OwnerReference` and finalizer state machines, zero-trust `NetworkPolicy` synthesis, `KataMicroVm` scheduling, and a pure reconciler.

To complete the production Kubernetes governance surface for autonomous agent workloads, `k8` requires:
1. **Least-Privilege RBAC (`k8-api::rbac`)**: Dedicated workload `ServiceAccount` synthesis with `automountServiceAccountToken: false`, scoped read-only `Role`/`RoleBinding` builders, and static auditing against wildcard verbs/resources, privilege escalation verbs (`escalate`, `bind`, `impersonate`), and unscoped `secrets` access.
2. **Namespace Quota & Kata Memory Overhead Governance (`k8-api::quota`)**: Deterministic `ResourceQuota` and `LimitRange` synthesis, plus integer permille (`0..=1000+`) headroom evaluation that accounts for both container resource limits and fixed per-pod Kata MicroVM hypervisor memory overhead (`256Mi` default) before admitting workloads.
3. **Ephemeral Scratch Volumes & Volume Hygiene (`k8-api::storage`)**: Bounded `emptyDir` scratch volume synthesis (`sizeLimit` required) for `readOnlyRootFilesystem: true` containers, path-traversal-free mount path validation, and static auditing rejecting `hostPath`, `docker.sock`, and unbounded `emptyDir` volumes.
4. **Pure Validating Admission Engine (`k8-api::admission`)**: Composable multi-gate admission pipeline producing deterministic `AdmissionReviewOutcome` verdicts and BLAKE3 decision digests without network or disk I/O.

## EARS Requirements

1. **WHEN** an `AgentWorkload` is synthesized into a `Job` or bundle, **THE SYSTEM SHALL** generate a dedicated `ServiceAccount` with `automountServiceAccountToken: Some(false)` unless explicit API access is requested.
2. **IF** an RBAC `Role` contains wildcard `apiGroups` (`"*"`), wildcard `resources` (`"*"`), wildcard `verbs` (`"*"`), privilege-escalation verbs (`"escalate"`, `"bind"`, `"impersonate"`), or `"secrets"` access without explicit `resourceNames` and read-only verbs (`"get"`), **THEN THE SYSTEM SHALL** reject the `Role` during static RBAC auditing.
3. **WHEN** evaluating `AgentWorkload` admission against a `NamespaceQuotaSpec` and `QuotaUsageSnapshot`, **THE SYSTEM SHALL** add per-replica Kata MicroVM hypervisor memory overhead whenever `IsolationProfile::KataMicroVm` is selected, and **SHALL** reject the workload if projected CPU, memory, or pod count exceeds the hard quota ceiling.
4. **WHEN** mounting ephemeral scratch storage into a `readOnlyRootFilesystem: true` workload container, **THE SYSTEM SHALL** attach an `emptyDir` volume with an explicit positive `sizeLimit` `Quantity` and a validated clean mount path that does not target sensitive kernel or runtime paths (`/proc`, `/sys`, `/dev`, `/var/run`, `/etc/kubernetes`).
5. **IF** a `PodSpec` contains any `hostPath` volume, any `emptyDir` volume without a positive `sizeLimit`, or any `VolumeMount` with `..` path traversal or sensitive system mount targets, **THEN THE SYSTEM SHALL** reject the `PodSpec` during volume security auditing.
6. **WHEN** `evaluate_workload_admission` runs over an `AgentWorkload`, **THE SYSTEM SHALL** execute all domain validation gates deterministically in zero I/O and emit a BLAKE3 `decision_digest` over the canonical admission verdict.

## Invariants

- **Zero I/O in `k8-api`**: `rbac`, `quota`, `storage`, and `admission` modules perform zero network or filesystem I/O and contain zero `unsafe` blocks (`#![forbid(unsafe_code)]`).
- **Integer Quota Arithmetic**: All quota headroom and utilization calculations use exact integer millicores, bytes, and basis points / permille (`u64` / `u128`), avoiding floating-point non-determinism.
- **No Unbounded Ephemeral Storage**: Every synthesized or audited `emptyDir` volume must carry a strictly positive `sizeLimit` (`Quantity`).
- **No Ambient Kubernetes API Credentials**: Every synthesized `ServiceAccount` and `PodSpec` sets `automountServiceAccountToken: Some(false)` by default.

## Verification

- **Unit & Break-Check Tests**: Verified in `crates/k8-api/src/rbac.rs`, `crates/k8-api/src/quota.rs`, `crates/k8-api/src/storage.rs`, `crates/k8-api/src/admission.rs`, and `crates/k8-orchestrator/src/lib.rs` via `cargo xtask check --break-check`.
- **Deterministic Simulation Testing (DST)**: Verified across 100 seeds in `crates/k8-api/tests/dst.rs` (`dst_rbac_quota_storage_and_admission_100_seeds`).
- **Architectural Graph Audit**: Verified via `cargo xtask graph-audit` and `cargo xtask spec-check`.
