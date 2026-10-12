<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# k8 — Roadmap

> Kubernetes agent orchestrator, workload controller, and native CLI tooling for autonomous agent fleets.
> Repo: `unsigned-gg/k8` · Codename: `forseti` (The Dispute Arbitrator)

---

## Current State (2026-10-12)

- **v0.1.0** — Initial monorepo baseline established across four crates.
- Crates:
  - `k8-api`: Typed CRD schemas (`AgentWorkload`), JSONSchema derivation, and phase models.
  - `k8-core`: Resilient Kubernetes client primitives and typed error handling.
  - `k8-orchestrator`: Pure job specification builder and async cluster execution.
  - `k8`: CLI binary and background daemon entrypoint.
- Formal LeanSpec registry: [`specs/SPEC-0001-k8-architecture-and-roadmap.md`](specs/SPEC-0001-k8-architecture-and-roadmap.md).
- Verification status:
  - Clean worktree hygiene with ignored local lane personas.
  - Formatted across all crates (`make fmt-check` passing).
  - Clippy clean across all workspace targets (`make clippy` passing).
  - 100% test pass rate with unit test coverage across API, core, and orchestrator crates.
  - Fail-closed manifest boundary enforcement (`publish = false` on internal crates).

---

## Roadmap Horizons (LeanSpec 0001)

### Horizon 1: Monorepo Hardening & Clean Baseline (Complete)
- Establish strict worktree hygiene and automated format validation.
- Implement unit test suites for API serialization, error types, and pure job construction.
- Validate release binary compilation under `-j 2` concurrency throttling.

### Horizon 2: Multi-Agent Consensus & Pure Jury Engine
- Build zero-allocation domain arbitration state machines in `k8-orchestrator`.
- Implement Byzantine fault tolerant quorum algorithms inspired by Barbara Liskov.
- Reconcile conflicting multi-agent output claims before committing cluster state.
- Issue cryptographic BLAKE3 receipts verifying completed workload outputs.

### Horizon 3: Estate Subsystem Integration
- **`unsigned-gg/sbx`**: Mount Landlock LSM sandboxes and seccomp profiles in agent containers.
- **`unsigned-gg/kd`**: Provide in-pod `pidfd` process tree supervision and subreaper zombie harvesting.
- **`unsigned-gg/wak`**: Connect TCP accept-and-hold proxies for transparent scale-to-zero activation.

### Horizon 4: Autonomous Controller Daemon & Production GitOps
- Implement a continuous reconciler loop using `kube::runtime::Controller`.
- Synchronize `AgentWorkload` custom resource status with active cluster Jobs.
- Export OTLP metrics and structured tracing to estate observability collectors.
- Deploy via Helm and ArgoCD to the Cygnus estate cluster.

---

## Integration with Estate Infrastructure

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│  soma / PaaS │ ──────> │      k8      │ <────── │     wak      │
│  Dispatcher  │         │ Orchestrator │         │ Scale-to-0   │
└──────────────┘         └──────┬───────┘         └──────────────┘
                                │
                 ┌──────────────┴──────────────┐
                 ▼                             ▼
          ┌──────────────┐              ┌──────────────┐
          │     sbx      │              │      kd      │
          │ Landlock Jail│              │  Subreaper   │
          └──────────────┘              └──────────────┘
```

- **soma → k8:** Dispatches containerized agent reasoning tasks onto Kubernetes nodes.
- **wak → k8:** Holds incoming connections and wakes scale-to-zero agent microservices on demand.
- **k8 → sbx:** Enforces filesystem Landlock restrictions and dropped privileges inside agent pods.
- **k8 → kd:** Supervizes multi-process hierarchies inside containers to eliminate zombie processes.
