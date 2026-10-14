// SPDX-License-Identifier: Apache-2.0 OR MIT
//! YAML 1.2 Kubernetes manifest parsing and rendering backed by `serde-saphyr`.

use crate::selector::{validate_dns1123_label, LabelError};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Errors returned when decoding, validating, or serializing Kubernetes YAML manifests.
#[derive(Debug, Error)]
pub enum ManifestError {
    /// YAML deserialization failure.
    #[error("YAML manifest parse error: {0}")]
    Deserialize(#[from] serde_saphyr::Error),

    /// YAML serialization failure.
    #[error("YAML manifest serialize error: {0}")]
    Serialize(#[from] serde_saphyr::ser::Error),

    /// Required Kubernetes header field is empty.
    #[error("Kubernetes manifest missing required field '{0}'")]
    MissingField(&'static str),

    /// Object metadata failed RFC 1123 DNS label validation.
    #[error("invalid manifest metadata: {0}")]
    InvalidMetadata(#[from] LabelError),
}

/// Minimal Kubernetes object metadata extracted from a YAML manifest header.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct ManifestMetadata {
    /// Resource name (DNS-1123 label).
    #[serde(default)]
    pub name: String,
    /// Optional target namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Optional metadata labels.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// Envelope header (`apiVersion`, `kind`, `metadata`) of any Kubernetes resource manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestHeader {
    /// Kubernetes API group/version (for example `batch/v1` or `agent.unsigned.gg/v1alpha1`).
    pub api_version: String,
    /// Resource kind (for example `Job` or `AgentWorkload`).
    pub kind: String,
    /// Resource metadata.
    pub metadata: ManifestMetadata,
}

impl ManifestHeader {
    /// Validate that `apiVersion`, `kind`, and `metadata.name` are well-formed.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.api_version.trim().is_empty() {
            return Err(ManifestError::MissingField("apiVersion"));
        }
        if self.kind.trim().is_empty() {
            return Err(ManifestError::MissingField("kind"));
        }
        if self.metadata.name.trim().is_empty() {
            return Err(ManifestError::MissingField("metadata.name"));
        }
        validate_dns1123_label(&self.metadata.name)?;
        if let Some(ns) = &self.metadata.namespace {
            validate_dns1123_label(ns)?;
        }
        Ok(())
    }
}

/// Parse a single Kubernetes manifest document from a YAML 1.2 string.
pub fn from_yaml_manifest<T: DeserializeOwned>(yaml: &str) -> Result<T, ManifestError> {
    Ok(serde_saphyr::from_str(yaml)?)
}

/// Parse a multi-document Kubernetes YAML stream separated by `---`.
pub fn from_multi_yaml_manifests<T: DeserializeOwned>(yaml: &str) -> Result<Vec<T>, ManifestError> {
    Ok(serde_saphyr::from_multiple(yaml)?)
}

/// Serialize a typed Kubernetes resource into a YAML 1.2 document string.
pub fn to_yaml_manifest<T: Serialize>(resource: &T) -> Result<String, ManifestError> {
    Ok(serde_saphyr::to_string(resource)?)
}

/// Render a slice of typed Kubernetes resources as a multi-document YAML stream separated by `---`.
pub fn render_multi_yaml_manifests<T: Serialize>(resources: &[T]) -> Result<String, ManifestError> {
    Ok(serde_saphyr::to_string_multiple(resources)?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_document_yaml_roundtrip() {
        let h1 = ManifestHeader {
            api_version: "agent.unsigned.gg/v1alpha1".to_string(),
            kind: "AgentWorkload".to_string(),
            metadata: ManifestMetadata {
                name: "workload-alpha".to_string(),
                namespace: Some("agents".to_string()),
                labels: BTreeMap::new(),
            },
        };
        let h2 = ManifestHeader {
            api_version: "batch/v1".to_string(),
            kind: "Job".to_string(),
            metadata: ManifestMetadata {
                name: "job-beta".to_string(),
                namespace: Some("agents".to_string()),
                labels: BTreeMap::new(),
            },
        };

        let multi = render_multi_yaml_manifests(&[h1.clone(), h2.clone()]).expect("render multi");
        let parsed: Vec<ManifestHeader> =
            from_multi_yaml_manifests(&multi).expect("parse multi yaml");
        assert_eq!(parsed.len(), 2);
        parsed[0].validate().expect("h1 valid");
        parsed[1].validate().expect("h2 valid");
        assert_eq!(parsed[0], h1);
        assert_eq!(parsed[1], h2);
    }
}
