---
status: complete
created: 2026-10-14
tags: [kubernetes, reconciler, finalizer, network-policy, scheduling, jury, liskov]
priority: critical
---
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# SPEC-0002: Wave-1 Kubernetes Lifecycle, NetworkPolicy, Scheduling & Pure Reconciler Primitives

## 1. Status & Metadata

- **Status:** Complete
- **Authors:** Forseti <forseti@jury.unsigned.gg>
- **Reviewer:** Mimir <mimir@unsigned.gg>
- **Champion Inspiration:** Barbara Liskov (behavioral subtyping, algebraic state machines, Byzantine quorum consensus)
- **Target System:** `k8` (`crates/k8-api`, `crates/k8-core`, `crates/k8-orchestrator`, `crates/k8`)
- **Parent Spec:** [`SPEC-0001-k8-architecture-and-roadmap.md`](SPEC-0001-k8-architecture-and-roadmap.md)

---

## 2. Problem Statement

Wave-0 established resource quantities, RFC 1123 selectors, `PodSecurity` `restricted` contexts, YAML 1.2 manifest serialization via `serde-saphyr`, and `3f + 1` Byzantine jury quorums.
Production Kubernetes controllers require four additional zero-I/O primitive layers before autonomous reconciliation:

1. **Lifecycle & Ownership Algebra:** Deterministic `OwnerReference` construction, finalizer state transitions, and monotonic `WorkloadCondition` updates.
2. **Zero-Trust Network Isolation:** Default-deny `NetworkPolicy` synthesis and fail-closed CIDR egress validation.
3. **Node Isolation & Disruption Budgets:** Kata microVM runtime selection, GPU and agent-pool taint tolerations, hostname topology spread, and `PodDisruptionBudget` generation.
4. **Pure Controller State Machine:** A zero-I/O reconciliation function $T: S \times E \to (S, \text{Effects})$ that unifies lifecycle finalizers, child Job synthesis, and `3f + 1` BFT jury receipts.

---

## 3. Mathematical & Behavioral Invariants

### Invariant 1: Monotonic Condition Transition Timestamp Preservation

Let $C_t(k)$ be the observed condition of type $k$ at time $t$ with status $s_t \in \{\text{True}, \text{False}, \text{Unknown}\}$ and transition timestamp $\tau_t$.
When an update $C_{t+1}(k)$ arrives with status $s_{t+1}$ at timestamp $\tau_{t+1}$:

$$\tau_{\text{effective}} = \begin{cases} \tau_t & \text{if } s_{t+1} = s_t \\ \tau_{t+1} & \text{if } s_{t+1} \neq s_t \end{cases}$$

Condition updates must never advance `lastTransitionTime` when `status` remains unchanged.

### Invariant 2: Single-Controller Ownership & Foreground Garbage Collection

Every child resource $R \in \{\text{Job}, \text{NetworkPolicy}, \text{PodDisruptionBudget}\}$ synthesized for an `AgentWorkload` $W$ with UID $u_W$ must carry an `OwnerReference` $O(W)$ satisfying:

$$\text{Controller}(O(W)) = \text{true} \land \text{BlockOwnerDeletion}(O(W)) = \text{true} \land \text{UID}(O(W)) = u_W$$

### Invariant 3: Fail-Closed Zero-Trust Egress

Every workload `NetworkPolicy` $NP(W)$ must declare ` policyTypes = ["Ingress", "Egress"] ` with zero ingress rules.
Egress rules must reject wildcard CIDR blocks (`0.0.0.0/0` and `::/0`) at construction time.

### Invariant 4: Pure Reconciler Determinism

Let $W$ be an `AgentWorkload` and $O = (\text{Job}_{\text{obs}}, \text{Jury}_{\text{obs}}, t_{\text{now}})$ be the cluster observation tuple.
The pure reconciler function:

$$\text{reconcile\_workload\_pure}(W, O) \to \text{Result}\langle\text{ReconcilePlan}, \text{K8Error}\rangle$$

executes zero network or filesystem I/O and produces an ordered sequence of `ReconcileEffect` commands.

---

## 4. Requirements (EARS)

### Ubiquitous Requirements
- **[REQ-0002-01]** The `k8-api::lifecycle` module shall construct `OwnerReference` values with `controller = true` and `block_owner_deletion = true`.
- **[REQ-0002-02]** The `k8-api::lifecycle` module shall preserve `last_transition_time` when updating a `WorkloadCondition` whose `status` has not changed.
- **[REQ-0002-03]** The `k8-api::network` module shall reject `0.0.0.0/0` and `::/0` egress CIDRs with `NetworkPolicyError::UnrestrictedCidrForbidden`.

### Event-driven Requirements
- **[REQ-0002-04]** WHEN an `AgentWorkload` has `deletionTimestamp` set and carries the `agent.unsigned.gg/workload-cleanup` finalizer, the reconciler shall emit `DeleteChildJob` and `RemoveFinalizer` effects.
- **[REQ-0002-05]** WHEN an `AgentWorkload` Job reaches `Succeeded` and a `JuryQuorum` returns `VerdictOutcome::Committed`, the reconciler shall seal a BLAKE3 `ExecutionReceipt` and set `JuryVerified=True`.

### Unwanted Behavior Requirements
- **[REQ-0002-06]** IF a `JuryQuorum` returns `VerdictOutcome::Disputed`, THEN the reconciler shall transition the workload to `WorkloadPhase::Failed` with reason `ByzantineSplitDispute`.
- **[REQ-0002-07]** IF a manifest passed to `k8 apply` violates `PodSecurity` `restricted` invariants, THEN the CLI shall reject the manifest before cluster submission.

---

## 5. Verification

- Unit tests in `k8-api` (`lifecycle`, `network`, `scheduling`) and `k8-orchestrator` (`reconciler`).
- Deterministic Simulation Testing (`crates/k8-api/tests/dst.rs`) across 100 seeds verifying condition monotonicity, finalizer convergence, and network policy zero-trust auditing.
- Full workspace gate: `cargo xtask check --break-check`.
