// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `k8-core`: Core Kubernetes client, cluster configuration, and primitives.

use kube::Client;
use thiserror::Error;

/// Error types for `k8-core`.
#[derive(Debug, Error)]
pub enum K8Error {
    #[error("Kubernetes client error: {0}")]
    Kube(#[from] kube::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Timeout waiting for resource: {0}")]
    Timeout(String),
}

pub type Result<T> = std::result::Result<T, K8Error>;

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
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = namespace.into();
        self
    }

    /// Return reference to the underlying `kube::Client`.
    pub fn inner(&self) -> &Client {
        &self.client
    }

    /// Return the active default namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

#[cfg(test)]
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
}
