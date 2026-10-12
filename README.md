# k8 [![crates.io](https://img.shields.io/crates/v/k8.svg)](https://crates.io/crates/k8) [![docs.rs](https://docs.rs/k8/badge.svg)](https://docs.rs/k8) [![License: Apache-2.0 OR MIT](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE-APACHE)

> **k8**: Kubernetes agent orchestrator, workload controller, and native CLI tooling for autonomous agent fleets.

`k8` provides native Rust primitives and a lightning-fast CLI to dispatch, isolate, supervise, and clean up autonomous agent workloads on Kubernetes clusters.

---

## Features

- **Microsecond CLI Tooling (`k8`)**: Fast cluster status, one-shot agent execution, streaming logs, and lifecycle inspection.
- **Agent Workload CRD (`AgentWorkload`)**: Declarative Kubernetes Custom Resource Definition (`agent.unsigned.gg/v1alpha1`) for AI agent swarms.
- **Strict Jail & Containment**: Enforces non-root execution, dropped capabilities, and sandboxed filesystem isolation on all dispatched agent pods.
- **Scale-to-Zero & Active Reaping**: Automatic job lifecycle supervision with deadline enforcement and instant garbage collection.
- **Monorepo Architecture**:
  - `k8`: Unified CLI tool and orchestrator binary (`cargo install k8`).
  - `k8-orchestrator`: Workload reconciler, scheduler, and supervisor engine.
  - `k8-api`: Typed CRD schemas and Kubernetes resource models.
  - `k8-core`: Resilient cluster connection, kube client wrappers, and authentication.

---

## Installation

```bash
cargo install k8
```

Or build from source:

```bash
git clone https://github.com/unsigned-gg/k8.git
cd k8
cargo build --release -j 2
```

---

## Usage

### Check Cluster & Agent Status

```bash
k8 status
```

### Dispatch an Agent Workload

```bash
k8 run ghcr.io/unsigned-gg/agent:latest \
    --role researcher \
    --cpu 2 \
    --memory 4Gi \
    --timeout 3600 \
    --command "agent" \
    --args "solve" "--ticket" "CER-42"
```

### List Active Agent Workloads

```bash
k8 list
```

### Terminate a Workload

```bash
k8 stop agent-9a4f21e0
```

### Run the Background Orchestrator Daemon

```bash
k8 daemon
```

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

This repository follows the unsigned constitution: [Privacy, Freedom, Dignity](https://github.com/unsigned-gg/.github/blob/main/PRIVACY_FREEDOM_DIGNITY.md) · [Guiding Principles](https://github.com/unsigned-gg/.github/blob/main/GUIDING_PRINCIPLES.md) · [Community Standards](https://github.com/unsigned-gg/.github/blob/main/COMMUNITY_STANDARDS.md) · [Brand Voice](https://github.com/unsigned-gg/.github/blob/main/BRAND_VOICE.md).
