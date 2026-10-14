---
id: SPEC-0005
title: Node Cordon/Drain Eviction Planner, Immutable Field Drift Detector, and Workload Priority Tiers
status: Active
created: 2026-10-14
owners:
  - forseti
  - mimir
---

# SPEC-0005: Node Cordon/Drain Eviction Planner, Immutable Field Drift Detector, and Workload Priority Tiers

## Summary

Defines Wave-4 pure zero-I/O Kubernetes control-plane primitives in `k8-api` (`drain.rs`, `drift.rs`, `priority.rs`), wires priority & grace-period controls into `AgentWorkloadSpec` and `k8-orchestrator`, and exposes `k8 drain-plan` and `k8 drift` CLI subcommands:

1. **Node Cordon/Drain & Eviction Safety Planner (`k8_api::drain`)**: Evaluates whether a target Kubernetes node can be safely cordoned (`spec.unschedulable = true`) and drained by classifying pods on the node (mirror pods, `DaemonSet` pods, unmanaged local storage), enforcing per-`PodDisruptionBudget` (`policy/v1`) remaining disruption budgets, and verifying via First-Fit Decreasing (FFD) bin-packing that all evicted pods fit onto surviving ready/schedulable cluster nodes (accounting for `kata` runtime requirements and the `256Mi` Kata hypervisor memory overhead). Also synthesizes typed `Node` cordon patches and `policy/v1` `Eviction` manifests.
2. **Immutable Field & StatefulSet PVC Template Drift Detector (`k8_api::drift`)**: Compares desired vs. live Kubernetes `StatefulSet` (`apps/v1`), `Job` (`batch/v1`), and `PersistentVolumeClaim` (`core/v1`) resources prior to Server-Side Apply (`Patch::Apply`) to detect immutable field mutations (`spec.volumeClaimTemplates`, `spec.serviceName`, `spec.selector`, `spec.completionMode`, `storageClassName`, `accessModes`, or storage shrinkage) and classify remediation strategies (`InPlaceApply`, `OrphanRecreateWithPvcExpand`, `DeleteAndRecreate`, or `RejectedForbiddenMutation`).
3. **Workload Priority Tiers, Preemption & Termination Grace Period Contracts (`k8_api::priority`)**: Models `scheduling.k8s.io/v1` `PriorityClass` tiers (`EstateCoordinator`, `InteractiveAgent`, `BatchResearch`, `SpotScavenger`), synthesizes `PriorityClass` manifests with explicit `preemptionPolicy` (`PreemptLowerPriority` or `Never`), and audits pod `priorityClassName` and `terminationGracePeriodSeconds` to prevent privilege escalation into `system-node-critical` / `system-cluster-critical` or unbounded termination delays.

## Motivation

- **Estate Safety Rule ("Never drain a node without confirming workloads can move")**: Draining a node in a mixed Kata/standard cluster without checking PDB budgets and destination Kata-adjusted memory headroom causes stuck evictions or `Pending` pods.
- **GitOps / SSA Sync Failures on Immutable Fields**: Kubernetes rejects in-place mutations to `StatefulSet.spec.volumeClaimTemplates`, `Job.spec.selector`, and PVC shrinkage with `422 Invalid`. Detecting and classifying immutable drift in pure Rust before issuing `Patch::Apply` prevents reconciliation loops from wedging.
- **Bounded Preemption & Graceful Termination**: Batch research jobs must not preempt peer batch jobs (`preemptionPolicy: Never`), and agent workloads must never claim reserved `system-*` priority classes or block node drains with unbounded `terminationGracePeriodSeconds`.

## Design

### 1. Node Cordon/Drain & Eviction Safety Planner (`k8_api::drain`)
- `DrainCandidatePod`, `PdbBudgetSnapshot`, `DrainClusterContext`, `PodEvictionAction`, `DrainBlockReason`, `NodePlacementAssignment`, `DrainPlanReport`.
- `evaluate_node_drain(ctx: &DrainClusterContext) -> DrainPlanReport`:
  1. Classifies static mirror pods (`SkippedMirrorPod`) and `DaemonSet` pods (`SkippedDaemonSetPod`).
  2. Rejects pods with unmanaged local storage when `allow_empty_dir_erasure == false` (`BlockedByLocalStorage`).
  3. Decrements per-PDB `disruptions_allowed` in priority/deterministic order; blocks pods whose PDB has `0` disruptions remaining (`PdbDisruptionBudgetExhausted`).
  4. Sorts evictable pods in First-Fit Decreasing (FFD) order by effective memory (`memory_bytes + 256Mi` if `KataMicroVm`, tie-broken by CPU and `namespace/name`) and assigns each pod to a surviving `ready && !unschedulable` node that satisfies `kata_runtime_capable` (for Kata pods) and has sufficient remaining allocatable CPU and memory.
  5. Emits `safe_to_drain: true` iff `blockers.is_empty()`, along with a deterministic 64-bit FNV-1a `plan_digest`.
- `build_pod_eviction(namespace, pod_name, grace_period_seconds)` synthesizes a `k8s_openapi::api::policy::v1::Eviction`.

### 2. Immutable Field & StatefulSet PVC Drift Detector (`k8_api::drift`)
- `DriftRemediationStrategy`: `InPlaceApply`, `OrphanRecreateWithPvcExpand`, `DeleteAndRecreate`, `RejectedForbiddenMutation`.
- `audit_statefulset_immutable_drift(live: &StatefulSet, desired: &StatefulSet) -> ImmutableDriftReport`.
- `audit_job_immutable_drift(live: &Job, desired: &Job) -> ImmutableDriftReport`.
- `audit_pvc_mutation(live: &PersistentVolumeClaim, desired: &PersistentVolumeClaim) -> ImmutableDriftReport`.

### 3. Priority Classes & Grace Period Contracts (`k8_api::priority`)
- `WorkloadPriorityTier`: `EstateCoordinator` (`100_000`, `PreemptLowerPriority`), `InteractiveAgent` (`50_000`, `PreemptLowerPriority`), `BatchResearch` (`10_000`, `Never`), `SpotScavenger` (`1_000`, `Never`).
- `build_priority_class(tier: WorkloadPriorityTier) -> PriorityClass`.
- `audit_pod_priority_and_grace_period(pod_spec: &PodSpec, max_grace_seconds: u64) -> Result<(), PriorityError>`.

## Invariants

- **INV-0005-01 (Drain Capacity & Kata Conservation)**: Whenever `evaluate_node_drain` returns `safe_to_drain == true`, every non-skipped pod on the target node has an explicit `NodePlacementAssignment` on a surviving ready, schedulable node whose post-placement CPU and Kata-adjusted memory (`container_mem + 256Mi * kata_pods`) never exceed `allocatable`.
- **INV-0005-02 (PDB Budget Conservation)**: Across any single `evaluate_node_drain` plan, the number of pods evicted under any `PodDisruptionBudget` `P` never exceeds `P.disruptions_allowed`.
- **INV-0005-03 (Monotonic PVC Expansion & StatefulSet Drift Classification)**: Shrinking a PVC or `volumeClaimTemplate` storage request is always classified as `RejectedForbiddenMutation`; increasing `volumeClaimTemplate` storage with all other immutable fields identical is classified as `OrphanRecreateWithPvcExpand`.
- **INV-0005-04 (Reserved Priority Containment)**: `audit_pod_priority_and_grace_period` rejects `system-node-critical` and `system-cluster-critical` priority classes for agent workloads and rejects `terminationGracePeriodSeconds` exceeding `MAX_TERMINATION_GRACE_SECONDS` (`300s`).

## Verification

- Unit tests in `crates/k8-api/src/drain.rs`, `crates/k8-api/src/drift.rs`, `crates/k8-api/src/priority.rs`, and `crates/k8/src/main.rs`.
- 100-seed Deterministic Simulation Testing (`DST`) in `crates/k8-api/tests/dst.rs` (`dst_node_drain_binpacking_pdb_and_immutable_drift_100_seeds`).
