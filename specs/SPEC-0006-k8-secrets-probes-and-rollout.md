---
id: SPEC-0006
title: Content-Addressed Immutable Configs, Secret Hygiene, Probe Timing & Rollout Quorum Algebra
status: Active
created: 2026-10-14
owners:
  - forseti
  - mimir
---

# SPEC-0006: Content-Addressed Immutable Configs, Secret Hygiene, Probe Timing & Rollout Quorum Algebra

## Summary

Defines Wave-5 pure zero-I/O Kubernetes primitives in `k8-api` (`secrets.rs`, `probes.rs`), wires secret-hygiene and probe validation into `evaluate_workload_admission` (`AdmissionGate::SecretAndTokenHygiene`, `AdmissionGate::ProbeTiming`) and `k8-orchestrator`, and exposes `k8 configmap` and `k8 rollout-check` CLI subcommands:

1. **Content-Addressed Immutable ConfigMap & Secret Synthesis (`k8_api::secrets`)**: Builds `core/v1` `ConfigMap` and `Secret` (`type: Opaque`) manifests with `immutable: Some(true)` and a deterministic 8-hex-character 64-bit FNV-1a content-hash suffix (`<base-name>-<hash8>`) computed over sorted `(key, value)` entries. Ensures every configuration change produces a new immutable resource name so referencing pod templates roll cleanly without mutable-config drift.
2. **Zero-Plaintext Secret Env & KEP-1205 Bound Token Auditing (`k8_api::secrets`)**: Audits `PodSpec` containers and `initContainers` to reject plaintext `env[].value` or `ConfigMapKeyRef` bindings on secret-named environment variables (`*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*CRED*`, `*PRIVATE*`, `*PASSWD*`) and audits projected `serviceAccountToken` volume sources to enforce explicit `audience` and bounded `expirationSeconds` (`600..=3600`, KEP-1205). Also provides `build_projected_token_volume` for bound OIDC token mounts.
3. **Probe Timing, Non-Shell Handler & Startup Window Auditing (`k8_api::probes`)**: Builds and audits `core/v1` `Probe` (`startupProbe`, `readinessProbe`, `livenessProbe`) specifications, rejecting shell-invoking `exec` probes (`sh`, `bash`, `/bin/sh`, `/bin/bash`, `dash`, `zsh`), enforcing `1 <= timeoutSeconds <= periodSeconds`, and verifying that when both `startupProbe` and `livenessProbe` are present, the startup budget (`startup.failureThreshold * startup.periodSeconds`) is at least the liveness failure window (`liveness.failureThreshold * liveness.periodSeconds`).
4. **RollingUpdate vs. PodDisruptionBudget Quorum Conservation (`k8_api::probes`)**: Evaluates `RolloutQuorumSpec` (`replicas`, `max_unavailable`, `max_surge`, `pdb_min_available`) to verify that a rolling update cannot stall (`max_unavailable == 0 && max_surge == 0`) or violate the `PodDisruptionBudget` minimum available floor (`replicas - max_unavailable >= pdb_min_available`), and computes the remaining concurrent node-drain disruption slack during an active rollout.

## Motivation

- **Estate Safety Rule ("Never commit API keys, tokens, or secrets in plaintext; check the whole body")**: Kubernetes workloads frequently leak credentials via literal `env[].value` in PodSpecs or mount unbounded legacy service account tokens. Fail-closed admission auditing catches plaintext env literals and unbounded `serviceAccountToken` projections before they reach the cluster.
- **Immutable ConfigMaps & Secrets (KEP-1412)**: Setting `immutable: true` with a deterministic content-hash suffix eliminates kubelet watch load on `ConfigMap`/`Secret` objects and prevents silent partial config reloads across running pods.
- **Probe-Induced CrashLoops & Rollout/Drain Deadlocks**: Misconfigured `livenessProbe` timeouts (`timeoutSeconds > periodSeconds`), shell-spawned `exec` probes that zombie under PID pressure, and `RollingUpdate` `maxUnavailable` budgets that breach `PodDisruptionBudget.spec.minAvailable` are leading causes of production rollout outages.

## Design

### 1. Content-Addressed Immutable ConfigMaps, Secrets & Token Projection (`k8_api::secrets`)
- `compute_kv_content_hash(entries: &BTreeMap<String, String>) -> String` (8-hex-char lowercase FNV-1a).
- `build_immutable_config_map(base_name: &str, namespace: &str, data: &BTreeMap<String, String>) -> Result<ConfigMap, SecretHygieneError>`.
- `build_immutable_secret(base_name: &str, namespace: &str, string_data: &BTreeMap<String, String>) -> Result<Secret, SecretHygieneError>` (verifies every secret value has non-zero trimmed body length, per Estate Secret Verification rule).
- `BoundTokenProjectionSpec`, `build_projected_token_volume(spec: &BoundTokenProjectionSpec) -> Result<(Volume, VolumeMount), SecretHygieneError>`.
- `audit_pod_secret_and_token_hygiene(pod_spec: &PodSpec) -> Result<(), SecretHygieneError>`.

### 2. Probe Timing & Rollout Quorum Algebra (`k8_api::probes`)
- `HttpProbeSpec`, `build_http_get_probe(spec: &HttpProbeSpec) -> Result<Probe, ProbeError>`.
- `audit_pod_probes(pod_spec: &PodSpec) -> Result<(), ProbeError>`.
- `RolloutQuorumSpec`, `RolloutQuorumReport`, `evaluate_rollout_quorum(spec: &RolloutQuorumSpec) -> Result<RolloutQuorumReport, ProbeError>`.

## Invariants

- **INV-0006-01 (Content-Addressed Immutability)**: `build_immutable_config_map` and `build_immutable_secret` always emit `immutable == Some(true)` and a deterministic DNS-1123 name `<base-name>-<hash8>` that changes iff the `(key, value)` map changes. Empty or whitespace-only secret bodies are rejected fail-closed.
- **INV-0006-02 (Zero Plaintext Secret Env & Bounded Token Projection)**: `audit_pod_secret_and_token_hygiene` rejects any container or initContainer `EnvVar` whose name matches `*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*CRED*`, `*PRIVATE*`, or `*PASSWD*` unless it is sourced exclusively from `valueFrom.secretKeyRef` (with `optional != Some(true)` and non-empty `name`/`key`), and rejects any projected `serviceAccountToken` volume lacking a non-empty `audience` or with `expirationSeconds` outside `600..=3600`.
- **INV-0006-03 (Probe Timing & Shell-Free Handler Soundness)**: `audit_pod_probes` rejects any probe with `periodSeconds <= 0`, `timeoutSeconds <= 0`, `timeoutSeconds > periodSeconds`, `failureThreshold <= 0`, shell `exec` commands, or `startup_window_seconds < liveness_window_seconds`.
- **INV-0006-04 (Rollout vs. PDB Quorum Conservation)**: `evaluate_rollout_quorum` guarantees `min_ready_during_rollout = replicas - max_unavailable >= pdb_min_available` and `max_unavailable > 0 || max_surge > 0`, returning exact `concurrent_drain_slack = min_ready_during_rollout - pdb_min_available`.

## Verification

- Unit tests in `crates/k8-api/src/secrets.rs`, `crates/k8-api/src/probes.rs`, and `crates/k8/src/main.rs`.
- 100-seed Deterministic Simulation Testing (`DST`) in `crates/k8-api/tests/dst.rs` (`dst_immutable_configs_secret_hygiene_probes_and_rollout_quorum_100_seeds`).
