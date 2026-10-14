// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `k8-core`: Core Kubernetes client, Server-Side Apply, dynamic YAML 1.2 manifest parsing,
//! and cluster primitives.

use k8_api::{ManifestError, SecurityViolation, SpecValidationError};
use kube::api::{
    Api, DeleteParams, DynamicObject, ListParams, Patch, PatchParams, PropagationPolicy,
};
use kube::{Client, Resource};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use thiserror::Error;

/// Canonical Kubernetes Server-Side Apply field manager identifier for `k8`.
pub const FIELD_MANAGER: &str = "k8-orchestrator";

/// Error types for `k8-core` and higher-level orchestrator operations.
#[derive(Debug, Error)]
pub enum K8Error {
    /// Underlying `kube::Error` returned by the Kubernetes API server or client.
    #[error("Kubernetes client error: {0}")]
    Kube(#[from] kube::Error),

    /// Cluster or client configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Requested Kubernetes resource was not found.
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// JSON serialization or deserialization failure.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// YAML 1.2 manifest parsing or serialization failure.
    #[error("Manifest error: {0}")]
    Manifest(#[from] ManifestError),

    /// Workload specification failed validation.
    #[error("Workload specification invalid: {0}")]
    InvalidSpec(#[from] SpecValidationError),

    /// PodSpec violated Kubernetes PodSecurity `restricted` invariants.
    #[error("PodSecurity restricted audit failed with {0:?}")]
    SecurityAudit(Vec<SecurityViolation>),

    /// Operation timed out waiting for a resource condition.
    #[error("Timeout waiting for resource: {0}")]
    Timeout(String),
}

/// Alias for `std::result::Result<T, K8Error>`.
pub type Result<T> = std::result::Result<T, K8Error>;

/// Construct [`PatchParams`] configured for Kubernetes Server-Side Apply with [`FIELD_MANAGER`].
#[must_use]
pub fn server_side_apply_params(force: bool) -> PatchParams {
    let params = PatchParams::apply(FIELD_MANAGER);
    if force {
        params.force()
    } else {
        params
    }
}

/// Construct [`DeleteParams`] with foreground cascading garbage collection.
#[must_use]
pub fn delete_foreground_params() -> DeleteParams {
    DeleteParams {
        propagation_policy: Some(PropagationPolicy::Foreground),
        ..Default::default()
    }
}

/// Construct [`ListParams`] filtered by a label selector expression.
#[must_use]
pub fn list_by_selector(selector: &str) -> ListParams {
    ListParams::default().labels(selector)
}

/// Parse one or more Kubernetes [`DynamicObject`] manifests from a YAML 1.2 stream (`---`).
pub fn parse_dynamic_manifests(yaml: &str) -> Result<Vec<DynamicObject>> {
    let docs: Vec<DynamicObject> =
        serde_saphyr::from_multiple(yaml).map_err(ManifestError::from)?;
    for doc in &docs {
        let name = doc.metadata.name.as_deref().unwrap_or("");
        if name.trim().is_empty() {
            return Err(K8Error::Manifest(ManifestError::MissingField(
                "metadata.name",
            )));
        }
    }
    Ok(docs)
}

/// Central client wrapper for interacting with a Kubernetes cluster.
#[derive(Clone)]
pub struct K8Client {
    client: Client,
    namespace: String,
}

impl K8Client {
    /// Create a new `K8Client` using standard default config (in-cluster SA or local kubeconfig).
    pub async fn default_client() -> Result<Self> {
        let client = Client::try_default().await?;
        let namespace = std::env::var("K8S_NAMESPACE").unwrap_or_else(|_| "default".to_string());
        Ok(Self { client, namespace })
    }

    /// Create a client with an explicit namespace.
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = namespace.into();
        self
    }

    /// Return a reference to the underlying `kube::Client`.
    #[must_use]
    pub fn inner(&self) -> &Client {
        &self.client
    }

    /// Return the active default namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Server-Side Apply a namespaced Kubernetes resource idempotently.
    pub async fn apply_namespaced<K>(&self, name: &str, resource: &K, force: bool) -> Result<K>
    where
        K: Resource<Scope = k8s_openapi::NamespaceResourceScope>
            + Clone
            + Serialize
            + DeserializeOwned
            + Debug,
        <K as Resource>::DynamicType: Default,
    {
        let api: Api<K> = Api::namespaced(self.client.clone(), &self.namespace);
        let pp = server_side_apply_params(force);
        let applied = api.patch(name, &pp, &Patch::Apply(resource)).await?;
        Ok(applied)
    }

    /// Server-Side Apply a status subresource on a namespaced Kubernetes resource.
    pub async fn patch_status_namespaced<K>(&self, name: &str, status_patch: &K) -> Result<K>
    where
        K: Resource<Scope = k8s_openapi::NamespaceResourceScope>
            + Clone
            + Serialize
            + DeserializeOwned
            + Debug,
        <K as Resource>::DynamicType: Default,
    {
        let api: Api<K> = Api::namespaced(self.client.clone(), &self.namespace);
        let pp = server_side_apply_params(true);
        let updated = api
            .patch_status(name, &pp, &Patch::Apply(status_patch))
            .await?;
        Ok(updated)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_k8_error_display() {
        let err = K8Error::Config("missing kubeconfig".to_string());
        assert_eq!(err.to_string(), "Configuration error: missing kubeconfig");

        let not_found = K8Error::NotFound("pod-123".to_string());
        assert_eq!(not_found.to_string(), "Resource not found: pod-123");

        let timeout = K8Error::Timeout("timed out waiting for ready".to_string());
        assert_eq!(
            timeout.to_string(),
            "Timeout waiting for resource: timed out waiting for ready"
        );
    }

    #[test]
    fn test_server_side_apply_and_delete_params() {
        let ssa = server_side_apply_params(true);
        assert_eq!(ssa.field_manager.as_deref(), Some(FIELD_MANAGER));
        assert!(ssa.force);

        let dp = delete_foreground_params();
        assert_eq!(dp.propagation_policy, Some(PropagationPolicy::Foreground));
    }

    #[test]
    fn test_parse_dynamic_manifests_multi_doc() {
        let yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: agent-config
  namespace: default
data:
  ROLE: arbitrator
---
apiVersion: batch/v1
kind: Job
metadata:
  name: agent-job-1
  namespace: default
"#;
        let docs = parse_dynamic_manifests(yaml).expect("parse multi-doc DynamicObject");
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0].metadata.name.as_deref(), Some("agent-config"));
        assert_eq!(docs[1].metadata.name.as_deref(), Some("agent-job-1"));
    }
}
