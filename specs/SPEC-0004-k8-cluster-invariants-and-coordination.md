---
status: Active
created: 2026-10-14
author: Forseti
---

# SPEC-0004: Cluster Invariants Auditor, Lease Leader Election, Backoff Policy, and Event Primitives

## Context

Waves 0–2 (`SPEC-0001` through `SPEC-0003`) established workload-scoped Kubernetes governance in `k8`: resource quantities, label selectors, Pod Security `Restricted` contexts, `serde-saphyr` YAML 1.2 manifests, $3f+1$ BFT jury receipts, controller `OwnerReference` and finalizer state machines, zero-trust `NetworkPolicy` synthesis, `KataMicroVm` scheduling, least-privilege RBAC, namespace quota + Kata MicroVM overhead governance, scratch volume hygiene, and the 7-gate pure admission engine.

To operate reliably at the cluster and control-plane level, `k8` requires two additional zero-I/O primitive domains and their integration into `k8-orchestrator` and the `k8` CLI:
1. **Cluster Invariants Auditor (`k8_api::invariants`)**: Pure verification of Cygnus/estate cluster invariants across provider node records, Kubernetes `Node` snapshots, scheduled pod footprints (accounting for per-pod Kata MicroVM hypervisor memory overhead), and `Service` endpoint readiness.
2. **Controller Coordination, Backoff & Structured Events (`k8_api::coordination`)**: Deterministic `coordination.k8s.io/v1` `Lease` leader election state machine (`Acquire`, `Renew`, `PreemptExpired`, `Standby`), bounded exponential backoff with deterministic seeded jitter (`SplitMix64`), and typed `core/v1::Event` synthesis for `AgentWorkload` transitions.
3. **Orchestrator & Reconciler Upgrade (`k8_orchestrator::reconciler`)**: Admission-gated reconciliation, owner-referenced RBAC (`ServiceAccount`, `Role`, `RoleBinding`) synthesis in `reconcile_workload_pure`, and structured Kubernetes `Event` emission.

## EARS Requirements

1. **WHEN** `evaluate_cluster_invariants` compares provider node inventory against Kubernetes `Node` snapshots, **THE SYSTEM SHALL** flag any provider node missing from Kubernetes (`NodeIdentityDrift`), any Kubernetes node missing a matching provider ID (`NodeIdentityDrift`), any unready node (`NodeReadiness`), and any agent-pool node lacking `kata` runtime capability when required (`KataRuntimeMissing`).
2. **WHEN** auditing scheduled pod footprints on a Kubernetes `Node`, **THE SYSTEM SHALL** add `DEFAULT_KATA_MEMORY_OVERHEAD_BYTES` (`256Mi`) to each `IsolationProfile::KataMicroVm` pod's memory request and **SHALL** emit a hard `KataMemoryOvercommit` or `NodeCpuOvercommit` error if total effective resource demand exceeds node allocatable capacity.
3. **IF** a `LoadBalancer` or `ClusterIP` `Service` snapshot reports zero ready endpoints, **THEN THE SYSTEM SHALL** emit a `ServiceZeroEndpoints` error in the `ClusterInvariantReport`.
4. **WHEN** `evaluate_lease_transition` evaluates a `LeaseStateSnapshot` at virtual time `now_ms`, **THE SYSTEM SHALL** grant leadership (`Acquire`, `Renew`, or `PreemptExpired`) to at most one candidate identity at any timestamp, incrementing `lease_transitions` strictly on holder handoff (`Acquire` or `PreemptExpired`) and preserving `lease_transitions` on same-holder `Renew`.
5. **WHEN** `compute_requeue_delay_ms` computes controller retry delay for `failure_count`, **THE SYSTEM SHALL** apply saturating exponential backoff capped at `max_delay_ms` with deterministic seeded jitter in `0..=jitter_permille`.
6. **WHEN** `reconcile_workload_pure` runs with an `AdmissionContext` in `ReconcileObservation`, **THE SYSTEM SHALL** evaluate the 7-gate admission pipeline before dispatching any child resources and **SHALL** transition the workload to `WorkloadPhase::Failed` with condition `Accepted=False` (`Reason=AdmissionDenied`) and a `Warning` `Event` if admission is denied.

## Invariants

- **INV-0004-01 (Zero-I/O Wave-0 Purity):** `k8_api::invariants` and `k8_api::coordination` reside in `k8-api` and perform zero network, filesystem, or clock I/O.
- **INV-0004-02 (Single-Leader Lease Mutual Exclusion):** Across any number of competing controller replicas evaluating the shared `LeaseStateSnapshot` at timestamp `now_ms`, at most one candidate receives `is_leader == true`.
- **INV-0004-03 (Node Kata Memory Conservation):** For every node in `ClusterInvariantReport::node_summaries`, `effective_memory_bytes` equals the sum of container memory requests plus `kata_pod_count * DEFAULT_KATA_MEMORY_OVERHEAD_BYTES`.
- **INV-0004-04 (Deterministic Report Digest):** `ClusterInvariantReport::report_digest` is a deterministic 64-bit FNV-1a hex commitment over all findings and node headroom summaries.
