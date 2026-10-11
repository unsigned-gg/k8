// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `k8`: Kubernetes agent orchestrator and native CLI tooling for autonomous agent fleets.

pub use k8_api as api;
pub use k8_core as core;
pub use k8_orchestrator as orchestrator;

pub use k8_core::{K8Client, K8Error, Result};
pub use k8_orchestrator::Orchestrator;
