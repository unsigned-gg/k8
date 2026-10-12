---
status: complete
created: 2026-10-12
tags: [roadmap, leanspec, ears, kubernetes, crd, consensus, jury, orchestrator, liskov]
priority: critical
---
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# SPEC-0001: k8 Architecture, Operational Invariants & Multi-Horizon Roadmap

## 1. Status & Metadata

- **Status:** Approved & Living
- **Authors:** Forseti <forseti@jury.unsigned.gg>
- **Reviewer:** Mimir <mimir@unsigned.gg>
- **Champion Inspiration:** Barbara Liskov (behavioral subtyping, Byzantine fault tolerance, distributed consensus)
- **Target System:** `k8` (`unsigned-gg/k8`, binaries: `k8`, crates: `k8-core`, `k8-api`, `k8-orchestrator`)
- **License:** CC-BY-4.0 / Apache-2.0 OR MIT

---

## 2. Problem Statement

Autonomous agent fleets require deterministic isolation, bounded execution, and consensus reconciliation on Kubernetes.
Standard Kubernetes Job controllers do not provide agent-specific lifecycle semantics.
Conventional controllers mix cluster I/O with scheduling and consensus logic.
This coupling prevents pure verification and violates behavioral subtyping.

`k8` resolves these limitations through a modular architecture.
The system separates pure domain consensus types from Kubernetes API calls.
The orchestrator enforces strict container sandboxing, non-root execution, dropped capabilities, and active reaping.

---

## 3. Mathematical Foundations & Operational Invariants

### Invariant 1: Zero-Allocation Pure Domain Layer & Behavioral Subtyping

Let $S$ represent the space of valid agent consensus states.
Let $E$ represent the finite alphabet of lifecycle events.
The state transition function $T$ is pure and deterministic:

$$T: S \times E \to S$$

Transitions must not perform network or filesystem I/O.
Per Barbara Liskov's substitution principle, any specialized arbitrator subtype must preserve all consensus invariants of $S$.
Subtypes must not weaken preconditions or strengthen postconditions.

### Invariant 2: Mandatory Host Throttling & Worker Concurrency Bound

Physical execution nodes run concurrent agent workloads.
To prevent CPU starvation and memory exhaustion, build and dispatch systems must limit concurrency:

$$\text{ParallelWorkers} \le 2$$

Every `cargo` invocation across Makefiles, Justfiles, and automation scripts must pass `-j 2`.

### Invariant 3: Strict Jail & Kernel Containment Bounds

Every dispatched agent Pod $P$ must enforce strict kernel containment.
Let $C(P)$ be the security context of Pod $P$:

$$\forall P, \quad \text{RunAsNonRoot}(C(P)) = \text{true} \land \text{AllowPrivilegeEscalation}(C(P)) = \text{false}$$

The container template drops all elevated Linux capabilities.
Containers execute with non-root UIDs to isolate tenant processes.

### Invariant 4: Monotonic Scale-to-Zero & Bounded Active Reaping

Let $t_{\text{start}}$ be the workload creation timestamp.
Let $t_{\text{limit}}$ be the configured execution deadline:

$$\text{ActiveDeadlineSeconds} \le t_{\text{limit}}$$

If execution exceeds $t_{\text{limit}}$, the Kubernetes API terminates the underlying Job.
The supervisor collects zombie processes, records terminal exit status, and cleans cluster resources.

### Invariant 5: Byzantine Fault Tolerance & Jury Reconciliation

When $N$ peer agents evaluate conflicting assertions, reconciliation requires Byzantine fault tolerance:

$$f < \frac{N}{3}$$

Where $f$ represents the maximum number of arbitrary or Byzantine agent failures.
The jury voting engine computes consensus across cryptographic output digests before applying state mutations.

---

## 4. Architecture & Interface

```
                          ┌───────────────────────────┐
                          │   k8 CLI / Daemon Entry   │
                          │        (crates/k8)        │
                          └─────────────┬─────────────┘
                                        │
           ┌────────────────────────────┴───────────────────────────┐
           ▼                                                        ▼
┌───────────────────────────┐                            ┌───────────────────────────┐
│     k8-orchestrator       │                            │          k8-api           │
│  - Job Dispatcher         │                            │  - AgentWorkload CRD      │
│  - Pure Job Builder       │                            │  - WorkloadPhase          │
│  - Sandbox Enforcement    │                            │  - AgentWorkloadStatus    │
└─────────────┬─────────────┘                            └───────────────────────────┘
              │                                                         ▲
              ▼                                                         │
┌───────────────────────────┐                                           │
│          k8-core          │                                           │
│  - K8Client Wrapper       │                                           │
│  - Namespaced Context     │                                           │
│  - Typed K8Error          │                                           │
└─────────────┬─────────────┘                                           │
              │                                                         │
              ▼                                                         │
┌───────────────────────────────────────────────────────────────────────┴───┐
│                           Kubernetes API Server                           │
│                      (Jobs, Pods, CRD Reconciler)                         │
└───────────────────────────────────────────────────────────────────────────┘
```

### Component Roles

1. **`crates/k8`**:
   Unified command-line interface and daemon runtime entrypoint.
   Exposes `status`, `run`, `list`, `stop`, and `daemon` commands.

2. **`crates/k8-orchestrator`**:
   Supervision engine.
   Provides pure `build_job` construction and async dispatch/termination routines.

3. **`crates/k8-api`**:
   Declarative Custom Resource Definition (`agent.unsigned.gg/v1alpha1`).
   Defines `AgentWorkloadSpec`, `WorkloadPhase`, and `AgentWorkloadStatus`.

4. **`crates/k8-core`**:
   Cluster connection abstraction and error management over `kube::Client`.

---

## 5. Multi-Horizon Roadmap

### Horizon 1: Core Substrate & Monorepo Hardening (Current)

- Deliver clean worktree hygiene across all crates.
- Enforce standard formatting with `cargo fmt --all -- --check`.
- Validate zero clippy warnings across workspace targets.
- Implement comprehensive unit tests for `k8-api`, `k8-core`, and `k8-orchestrator`.
- Enforce fail-closed manifest publishing boundaries (`publish = false` on internal crates).

### Horizon 2: Multi-Agent Consensus & Pure Jury State Machine

- Implement a zero-allocation jury reconciliation engine in `k8-orchestrator`.
- Model Byzantine fault tolerant voting quorums using Barbara Liskov's consensus principles.
- Add dispute arbitration state machines to resolve conflicting agent assertions.
- Generate cryptographic BLAKE3 attestation receipts for completed workloads.

### Horizon 3: Estate Subsystem Integration (sbx, kd, wak)

- **`unsigned-gg/sbx` Bridge:** Mount Landlock LSM and seccomp sandboxes inside agent containers.
- **`unsigned-gg/kd` Bridge:** Supervise in-pod process trees using `pidfd` descriptors and subreaper harvesting.
- **`unsigned-gg/wak` Bridge:** Connect scale-to-zero TCP accept-and-hold proxies for wake-on-arrival workflows.

### Horizon 4: Autonomous Controller Daemon & Production GitOps

- Build a continuous Kubernetes controller reconciliation loop via `kube::runtime::Controller`.
- Reconcile `AgentWorkload` custom resources with live cluster Job status.
- Export OTLP metrics and structured tracing to central telemetry sinks.
- Package Helm charts and configure ArgoCD deployment for the Cygnus estate cluster.

---

## 6. Requirements (EARS)

### Ubiquitous Requirements
- **[REQ-0001-01]** The `k8` orchestrator shall construct deterministic Kubernetes Job specifications from declared `AgentWorkloadSpec` inputs.
- **[REQ-0001-02]** The `k8-api` crate shall generate standard OpenAPI v3 schemas and Kubernetes CRDs under group `agent.unsigned.gg`.

### Event-driven Requirements
- **[REQ-0001-03]** WHEN the CLI receives a `run` command, the `k8-orchestrator` shall dispatch an isolated Kubernetes Job to the active namespace.
- **[REQ-0001-04]** WHEN an operator issues a `stop` command with a valid run ID, the orchestrator shall terminate the target Job.

### State-driven Requirements
- **[REQ-0001-05]** WHILE an agent workload executes in the `Running` phase, the orchestrator shall enforce non-root execution and privilege escalation restrictions.

### Optional Feature Requirements
- **[REQ-0001-06]** WHERE GPU resources are requested, the orchestrator shall configure NVIDIA container limits and resource requests.

### Unwanted Behavior Requirements
- **[REQ-0001-07]** IF an agent execution exceeds the declared timeout, THEN the Kubernetes cluster shall terminate the workload via `active_deadline_seconds`.
- **[REQ-0001-08]** IF a non-existent run ID is passed to `stop`, THEN the orchestrator shall return a typed `K8Error::NotFound` without crashing.

---

## 7. Verification & Test Matrix

All code changes must pass the following verification gates before merge:

1. **Format Check:**
   ```bash
   make fmt-check
   ```
2. **Compilation Check:**
   ```bash
   make check
   ```
3. **Clippy Lint Verification:**
   ```bash
   make clippy
   ```
4. **Unit Test Execution:**
   ```bash
   make test
   ```
5. **Release Build Verification:**
   ```bash
   make build-release
   ```

---

## 8. Notes & Devotions

- System architecture honors Barbara Liskov's foundational contributions to distributed systems and abstraction invariants.
- All technical documentation adheres to ASD-STE100 controlled language standards.
