// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Kubernetes RFC 1123 DNS label validation, canonical workload labels, and selector matching.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use thiserror::Error;

/// Canonical label key for application name.
pub const LABEL_APP_NAME: &str = "app.kubernetes.io/name";
/// Canonical label key for managing controller.
pub const LABEL_MANAGED_BY: &str = "app.kubernetes.io/managed-by";
/// Canonical label key for workload run identifier.
pub const LABEL_RUN_ID: &str = "unsigned.gg/run-id";
/// Canonical label key for agent persona or role.
pub const LABEL_AGENT_ROLE: &str = "unsigned.gg/agent-role";

/// Errors returned when validating Kubernetes object names, label keys, or label values.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LabelError {
    /// DNS-1123 label is empty or exceeds 63 characters.
    #[error("DNS-1123 label '{0}' must be between 1 and 63 characters")]
    InvalidDns1123Length(String),

    /// DNS-1123 label contains invalid characters or starts/ends with a hyphen.
    #[error("DNS-1123 label '{0}' must consist of lowercase alphanumeric characters or '-'")]
    InvalidDns1123Format(String),

    /// Label key prefix exceeds 253 characters or is malformed.
    #[error("invalid Kubernetes label key '{0}'")]
    InvalidLabelKey(String),

    /// Label value exceeds 63 characters or contains invalid characters.
    #[error("invalid Kubernetes label value '{0}'")]
    InvalidLabelValue(String),
}

/// Validate a string against RFC 1123 DNS label rules (`[a-z0-9]([-a-z0-9]*[a-z0-9])?`, max 63 chars).
pub fn validate_dns1123_label(value: &str) -> Result<(), LabelError> {
    if value.is_empty() || value.len() > 63 {
        return Err(LabelError::InvalidDns1123Length(value.to_string()));
    }
    let bytes = value.as_bytes();
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(LabelError::InvalidDns1123Format(value.to_string()));
    }
    if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
        return Err(LabelError::InvalidDns1123Format(value.to_string()));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Err(LabelError::InvalidDns1123Format(value.to_string()));
    }
    Ok(())
}

/// Validate a Kubernetes label key (`[prefix/]name`).
pub fn validate_label_key(key: &str) -> Result<(), LabelError> {
    if key.is_empty() {
        return Err(LabelError::InvalidLabelKey(key.to_string()));
    }
    let name = if let Some((prefix, rest)) = key.split_once('/') {
        if prefix.is_empty() || prefix.len() > 253 || rest.contains('/') {
            return Err(LabelError::InvalidLabelKey(key.to_string()));
        }
        for segment in prefix.split('.') {
            validate_dns1123_label(segment)
                .map_err(|_| LabelError::InvalidLabelKey(key.to_string()))?;
        }
        rest
    } else {
        key
    };

    if name.is_empty() || name.len() > 63 {
        return Err(LabelError::InvalidLabelKey(key.to_string()));
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(LabelError::InvalidLabelKey(key.to_string()));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_' || *b == b'.')
    {
        return Err(LabelError::InvalidLabelKey(key.to_string()));
    }
    Ok(())
}

/// Validate a Kubernetes label value (empty or `<= 63` alphanumeric/`-`/`_`/`.` characters).
pub fn validate_label_value(value: &str) -> Result<(), LabelError> {
    if value.is_empty() {
        return Ok(());
    }
    if value.len() > 63 {
        return Err(LabelError::InvalidLabelValue(value.to_string()));
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(LabelError::InvalidLabelValue(value.to_string()));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_' || *b == b'.')
    {
        return Err(LabelError::InvalidLabelValue(value.to_string()));
    }
    Ok(())
}

/// Construct the canonical `unsigned.gg` label set for an agent workload.
pub fn canonical_workload_labels(
    run_id: &str,
    agent_role: Option<&str>,
) -> Result<BTreeMap<String, String>, LabelError> {
    validate_dns1123_label(run_id)?;
    let mut labels = BTreeMap::new();
    labels.insert(LABEL_APP_NAME.to_string(), "k8-agent".to_string());
    labels.insert(LABEL_MANAGED_BY.to_string(), "k8".to_string());
    labels.insert(LABEL_RUN_ID.to_string(), run_id.to_string());
    if let Some(role) = agent_role {
        validate_dns1123_label(role)?;
        labels.insert(LABEL_AGENT_ROLE.to_string(), role.to_string());
    }
    Ok(labels)
}

/// Deterministic equality-based Kubernetes label selector.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct LabelSelector {
    /// Equality match requirements (`key = value`).
    pub match_labels: BTreeMap<String, String>,
}

impl LabelSelector {
    /// Create a new empty selector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            match_labels: BTreeMap::new(),
        }
    }

    /// Add a validated `key=value` requirement to the selector.
    pub fn with_label(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, LabelError> {
        let k = key.into();
        let v = value.into();
        validate_label_key(&k)?;
        validate_label_value(&v)?;
        self.match_labels.insert(k, v);
        Ok(self)
    }

    /// Return `true` if `candidate` satisfies all `match_labels` entries.
    #[must_use]
    pub fn matches(&self, candidate: &BTreeMap<String, String>) -> bool {
        self.match_labels
            .iter()
            .all(|(k, v)| candidate.get(k) == Some(v))
    }
}

impl fmt::Display for LabelSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (k, v) in &self.match_labels {
            if !first {
                f.write_str(",")?;
            }
            first = false;
            write!(f, "{k}={v}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_dns1123_validation() {
        assert!(validate_dns1123_label("agent-run-1").is_ok());
        assert!(validate_dns1123_label("researcher").is_ok());
        assert!(validate_dns1123_label("-bad").is_err());
        assert!(validate_dns1123_label("BadUpper").is_err());
        assert!(validate_dns1123_label("").is_err());
    }

    #[test]
    fn test_selector_matching_and_formatting() {
        let labels = canonical_workload_labels("agent-1234", Some("critic")).expect("valid labels");
        let selector = LabelSelector::new()
            .with_label(LABEL_MANAGED_BY, "k8")
            .expect("managed-by")
            .with_label(LABEL_AGENT_ROLE, "critic")
            .expect("role");

        assert!(selector.matches(&labels));
        assert_eq!(
            selector.to_string(),
            "app.kubernetes.io/managed-by=k8,unsigned.gg/agent-role=critic"
        );
    }
}
