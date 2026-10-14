// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `secrets`: Pure zero-I/O Kubernetes Content-Addressed Immutable `ConfigMap`/`Secret`
//! Synthesis, Secret Env Leak Auditing & KEP-1205 Bound Token Projections (`SPEC-0006`).
//!
//! Enforces estate secret verification and zero-plaintext-credential invariants:
//! - Content-addressed `ConfigMap` and `Secret` (`immutable: true`, `<base-name>-<hash8>`).
//! - Rejects empty/whitespace-only secret bodies (`INV-0006-01`).
//! - Rejects literal `env[].value` or `configMapKeyRef` on sensitive env var names
//!   (`*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*CRED*`, `*PRIVATE*`, `*PASSWD*`) (`INV-0006-02`).
//! - Enforces KEP-1205 bound `ServiceAccountTokenProjection` (`audience` non-empty,
//!   `expirationSeconds` in `600..=3600`) (`INV-0006-02`).

use crate::selector::{validate_dns1123_label, LabelError};
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, PodSpec, ProjectedVolumeSource, Secret, ServiceAccountTokenProjection,
    Volume, VolumeMount, VolumeProjection,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Minimum allowed bound `ServiceAccountTokenProjection` expiration in seconds (10 minutes, KEP-1205).
pub const MIN_TOKEN_EXPIRATION_SECONDS: i64 = 600;

/// Maximum allowed bound `ServiceAccountTokenProjection` expiration in seconds (1 hour, KEP-1205).
pub const MAX_TOKEN_EXPIRATION_SECONDS: i64 = 3600;

/// Default bound `ServiceAccountTokenProjection` expiration in seconds (1 hour).
pub const DEFAULT_TOKEN_EXPIRATION_SECONDS: i64 = 3600;

/// Default restrictive file mode (`0400` = `256` decimal) for projected token volumes.
pub const DEFAULT_PROJECTED_TOKEN_MODE: i32 = 0o400;

/// Substrings that classify an environment variable name as credential/secret-bearing (`INV-0006-02`).
pub const SENSITIVE_ENV_SUBSTRINGS: &[&str] = &[
    "KEY", "TOKEN", "SECRET", "PASSWORD", "CRED", "PRIVATE", "PASSWD",
];

/// Errors returned during content-addressed `ConfigMap`/`Secret` synthesis or pod secret/token auditing.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SecretHygieneError {
    /// Invalid DNS-1123 label for resource or volume name.
    #[error("invalid DNS-1123 name in secret/config primitive: {0}")]
    InvalidName(#[from] LabelError),

    /// Base name is too long to append `-<hash8>` within the 63-char DNS-1123 limit.
    #[error("base name `{0}` exceeds 54 characters; cannot append 8-char content hash within 63-char DNS-1123 limit")]
    BaseNameTooLong(String),

    /// `ConfigMap` or `Secret` key-value map is empty.
    #[error("immutable `{0}` must contain at least one key-value entry")]
    EmptyDataMap(&'static str),

    /// A `ConfigMap` or `Secret` key is empty or contains invalid characters.
    #[error("invalid data key `{0}`: keys must be non-empty ASCII alphanumeric, `-`, `_`, or `.`")]
    InvalidDataKey(String),

    /// A `Secret` entry has an empty or whitespace-only body (Estate Secret Verification rule).
    #[error("secret key `{0}` has an empty or whitespace-only body (check the whole body, never presence alone)")]
    EmptySecretValueBody(String),

    /// Sensitive environment variable uses a plaintext `value` instead of `valueFrom.secretKeyRef`.
    #[error("container `{container}` env var `{env_name}` matches a sensitive credential pattern and must not use a literal plaintext `value`")]
    PlaintextSensitiveEnvVar {
        /// Container name.
        container: String,
        /// Environment variable name.
        env_name: String,
    },

    /// Sensitive environment variable is not backed by a mandatory `secretKeyRef`.
    #[error("container `{container}` sensitive env var `{env_name}` must be sourced from a non-optional `valueFrom.secretKeyRef` with non-empty `name` and `key`")]
    InvalidSensitiveEnvSource {
        /// Container name.
        container: String,
        /// Environment variable name.
        env_name: String,
    },

    /// Projected `serviceAccountToken` volume source has an empty `audience`.
    #[error("projected serviceAccountToken in volume `{volume}` must specify a non-empty `audience` (KEP-1205)")]
    MissingProjectedTokenAudience {
        /// Volume name.
        volume: String,
    },

    /// Projected `serviceAccountToken` volume source has an missing or out-of-range `expirationSeconds`.
    #[error("projected serviceAccountToken in volume `{volume}` has expirationSeconds={expiration:?}, outside allowed range {MIN_TOKEN_EXPIRATION_SECONDS}..={MAX_TOKEN_EXPIRATION_SECONDS}")]
    InvalidProjectedTokenExpiration {
        /// Volume name.
        volume: String,
        /// Configured expiration seconds.
        expiration: Option<i64>,
    },

    /// Projected `serviceAccountToken` path is empty or contains `..` / leading `/`.
    #[error("projected serviceAccountToken path `{0}` must be a clean relative filename")]
    InvalidProjectedTokenPath(String),
}

/// Specification for a KEP-1205 bound `ServiceAccountTokenProjection` volume and mount (`SPEC-0006`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BoundTokenProjectionSpec {
    /// Volume name (`DNS-1123` label, e.g. `"bound-sa-token"`).
    pub volume_name: String,
    /// Absolute mount path inside the container (e.g. `"/var/run/secrets/tokens"`).
    pub mount_path: String,
    /// Relative file path inside `mount_path` (e.g. `"oidc-token"`).
    pub token_rel_path: String,
    /// Required OIDC token audience (e.g. `"https://openbao.unsigned.gg"`).
    pub audience: String,
    /// Token expiration in seconds (`600..=3600`).
    pub expiration_seconds: i64,
}

impl Default for BoundTokenProjectionSpec {
    fn default() -> Self {
        Self {
            volume_name: "bound-sa-token".to_owned(),
            mount_path: "/var/run/secrets/tokens".to_owned(),
            token_rel_path: "token".to_owned(),
            audience: "https://kubernetes.default.svc.cluster.local".to_owned(),
            expiration_seconds: DEFAULT_TOKEN_EXPIRATION_SECONDS,
        }
    }
}

/// Returns `true` if `env_name` (case-insensitive) contains any credential-identifying substring
/// (`KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `CRED`, `PRIVATE`, `PASSWD`) (`INV-0006-02`).
#[must_use]
pub fn is_sensitive_env_var_name(env_name: &str) -> bool {
    let upper = env_name.to_ascii_uppercase();
    SENSITIVE_ENV_SUBSTRINGS
        .iter()
        .any(|needle| upper.contains(needle))
}

/// Computes a deterministic 8-hex-character lowercase 64-bit FNV-1a content hash over sorted
/// `(key, value)` pairs (`INV-0006-01`).
#[must_use]
pub fn compute_kv_content_hash(entries: &BTreeMap<String, String>) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for (k, v) in entries {
        for b in k.as_bytes() {
            hash ^= u64::from(*b);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0100_0000_01b3);
        for b in v.as_bytes() {
            hash ^= u64::from(*b);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        hash ^= 0xfe;
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    let folded = (hash ^ (hash >> 32)) as u32;
    format!("{folded:08x}")
}

fn validate_data_key(key: &str) -> Result<(), SecretHygieneError> {
    if key.is_empty()
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(SecretHygieneError::InvalidDataKey(key.to_owned()));
    }
    Ok(())
}

fn build_content_addressed_name(
    base_name: &str,
    entries: &BTreeMap<String, String>,
) -> Result<String, SecretHygieneError> {
    validate_dns1123_label(base_name)?;
    if base_name.len() > 54 {
        return Err(SecretHygieneError::BaseNameTooLong(base_name.to_owned()));
    }
    let hash8 = compute_kv_content_hash(entries);
    let full_name = format!("{base_name}-{hash8}");
    validate_dns1123_label(&full_name)?;
    Ok(full_name)
}

/// Synthesizes a content-addressed, immutable Kubernetes `core/v1` [`ConfigMap`] (`INV-0006-01`).
///
/// # Errors
/// Returns [`SecretHygieneError`] if `base_name` or `namespace` is invalid, `data` is empty,
/// or any key contains invalid characters.
pub fn build_immutable_config_map(
    base_name: &str,
    namespace: &str,
    data: &BTreeMap<String, String>,
) -> Result<ConfigMap, SecretHygieneError> {
    validate_dns1123_label(namespace)?;
    if data.is_empty() {
        return Err(SecretHygieneError::EmptyDataMap("ConfigMap"));
    }
    for k in data.keys() {
        validate_data_key(k)?;
    }
    let name = build_content_addressed_name(base_name, data)?;
    Ok(ConfigMap {
        metadata: ObjectMeta {
            name: Some(name),
            namespace: Some(namespace.to_owned()),
            labels: Some(BTreeMap::from([
                (
                    "k8.unsigned.gg/config-base".to_owned(),
                    base_name.to_owned(),
                ),
                ("k8.unsigned.gg/immutable".to_owned(), "true".to_owned()),
            ])),
            ..Default::default()
        },
        data: Some(data.clone()),
        immutable: Some(true),
        ..Default::default()
    })
}

/// Synthesizes a content-addressed, immutable Kubernetes `core/v1` [`Secret`] (`type: Opaque`)
/// after verifying that every secret entry has a non-empty trimmed body (`INV-0006-01`).
///
/// # Errors
/// Returns [`SecretHygieneError`] if `base_name` or `namespace` is invalid, `string_data` is empty,
/// or any secret value body is empty/whitespace-only.
pub fn build_immutable_secret(
    base_name: &str,
    namespace: &str,
    string_data: &BTreeMap<String, String>,
) -> Result<Secret, SecretHygieneError> {
    validate_dns1123_label(namespace)?;
    if string_data.is_empty() {
        return Err(SecretHygieneError::EmptyDataMap("Secret"));
    }
    for (k, v) in string_data {
        validate_data_key(k)?;
        if v.trim().is_empty() {
            return Err(SecretHygieneError::EmptySecretValueBody(k.clone()));
        }
    }
    let name = build_content_addressed_name(base_name, string_data)?;
    Ok(Secret {
        metadata: ObjectMeta {
            name: Some(name),
            namespace: Some(namespace.to_owned()),
            labels: Some(BTreeMap::from([
                (
                    "k8.unsigned.gg/secret-base".to_owned(),
                    base_name.to_owned(),
                ),
                ("k8.unsigned.gg/immutable".to_owned(), "true".to_owned()),
            ])),
            ..Default::default()
        },
        string_data: Some(string_data.clone()),
        immutable: Some(true),
        type_: Some("Opaque".to_owned()),
        ..Default::default()
    })
}

/// Synthesizes a KEP-1205 bound `ServiceAccountTokenProjection` [`Volume`] and read-only [`VolumeMount`].
///
/// # Errors
/// Returns [`SecretHygieneError`] if the volume name, token path, audience, or expiration window is invalid.
pub fn build_projected_token_volume(
    spec: &BoundTokenProjectionSpec,
) -> Result<(Volume, VolumeMount), SecretHygieneError> {
    validate_dns1123_label(&spec.volume_name)?;
    if spec.audience.trim().is_empty() {
        return Err(SecretHygieneError::MissingProjectedTokenAudience {
            volume: spec.volume_name.clone(),
        });
    }
    if !(MIN_TOKEN_EXPIRATION_SECONDS..=MAX_TOKEN_EXPIRATION_SECONDS)
        .contains(&spec.expiration_seconds)
    {
        return Err(SecretHygieneError::InvalidProjectedTokenExpiration {
            volume: spec.volume_name.clone(),
            expiration: Some(spec.expiration_seconds),
        });
    }
    let rel = spec.token_rel_path.trim();
    if rel.is_empty() || rel.starts_with('/') || rel.contains("..") {
        return Err(SecretHygieneError::InvalidProjectedTokenPath(
            spec.token_rel_path.clone(),
        ));
    }

    let volume = Volume {
        name: spec.volume_name.clone(),
        projected: Some(ProjectedVolumeSource {
            default_mode: Some(DEFAULT_PROJECTED_TOKEN_MODE),
            sources: Some(vec![VolumeProjection {
                service_account_token: Some(ServiceAccountTokenProjection {
                    audience: Some(spec.audience.trim().to_owned()),
                    expiration_seconds: Some(spec.expiration_seconds),
                    path: rel.to_owned(),
                }),
                ..Default::default()
            }]),
        }),
        ..Default::default()
    };

    let mount = VolumeMount {
        name: spec.volume_name.clone(),
        mount_path: spec.mount_path.clone(),
        read_only: Some(true),
        ..Default::default()
    };

    Ok((volume, mount))
}

fn audit_container_env_hygiene(container: &Container) -> Result<(), SecretHygieneError> {
    if let Some(envs) = &container.env {
        for env_var in envs {
            if is_sensitive_env_var_name(&env_var.name) {
                if env_var.value.is_some() {
                    return Err(SecretHygieneError::PlaintextSensitiveEnvVar {
                        container: container.name.clone(),
                        env_name: env_var.name.clone(),
                    });
                }
                let valid_secret_ref = env_var
                    .value_from
                    .as_ref()
                    .and_then(|vf| vf.secret_key_ref.as_ref())
                    .is_some_and(|skr| {
                        !skr.name.trim().is_empty()
                            && !skr.key.trim().is_empty()
                            && skr.optional != Some(true)
                    });
                if !valid_secret_ref {
                    return Err(SecretHygieneError::InvalidSensitiveEnvSource {
                        container: container.name.clone(),
                        env_name: env_var.name.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Audits a [`PodSpec`] for zero plaintext sensitive environment variables and KEP-1205 bound
/// `serviceAccountToken` volume projections (`INV-0006-02`).
///
/// # Errors
/// Returns [`SecretHygieneError`] on the first credential leak or unbounded token projection found.
pub fn audit_pod_secret_and_token_hygiene(pod_spec: &PodSpec) -> Result<(), SecretHygieneError> {
    for container in &pod_spec.containers {
        audit_container_env_hygiene(container)?;
    }
    if let Some(init_containers) = &pod_spec.init_containers {
        for container in init_containers {
            audit_container_env_hygiene(container)?;
        }
    }

    if let Some(volumes) = &pod_spec.volumes {
        for vol in volumes {
            if let Some(proj) = &vol.projected {
                if let Some(sources) = &proj.sources {
                    for src in sources {
                        if let Some(sat) = &src.service_account_token {
                            let has_audience = sat
                                .audience
                                .as_deref()
                                .is_some_and(|a| !a.trim().is_empty());
                            if !has_audience {
                                return Err(SecretHygieneError::MissingProjectedTokenAudience {
                                    volume: vol.name.clone(),
                                });
                            }
                            match sat.expiration_seconds {
                                Some(exp)
                                    if (MIN_TOKEN_EXPIRATION_SECONDS
                                        ..=MAX_TOKEN_EXPIRATION_SECONDS)
                                        .contains(&exp) => {}
                                other => {
                                    return Err(
                                        SecretHygieneError::InvalidProjectedTokenExpiration {
                                            volume: vol.name.clone(),
                                            expiration: other,
                                        },
                                    );
                                }
                            }
                            if sat.path.trim().is_empty()
                                || sat.path.starts_with('/')
                                || sat.path.contains("..")
                            {
                                return Err(SecretHygieneError::InvalidProjectedTokenPath(
                                    sat.path.clone(),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{EnvVar, EnvVarSource, SecretKeySelector};

    #[test]
    fn builds_content_addressed_immutable_config_map_and_secret() {
        let mut data = BTreeMap::new();
        data.insert("LOG_LEVEL".to_owned(), "info".to_owned());
        let cm1 = build_immutable_config_map("agent-cfg", "agents", &data).unwrap();
        assert_eq!(cm1.immutable, Some(true));
        let name1 = cm1.metadata.name.clone().unwrap();
        assert!(name1.starts_with("agent-cfg-"));
        assert_eq!(name1.len(), "agent-cfg-".len() + 8);

        data.insert("LOG_LEVEL".to_owned(), "debug".to_owned());
        let cm2 = build_immutable_config_map("agent-cfg", "agents", &data).unwrap();
        assert_ne!(cm1.metadata.name, cm2.metadata.name);

        // Empty secret value body is rejected fail-closed
        let bad_secret = BTreeMap::from([("API_KEY".to_owned(), "   ".to_owned())]);
        assert!(matches!(
            build_immutable_secret("agent-sec", "agents", &bad_secret),
            Err(SecretHygieneError::EmptySecretValueBody(_))
        ));
    }

    #[test]
    fn audits_sensitive_env_vars_and_projected_tokens() {
        let (vol, mount) =
            build_projected_token_volume(&BoundTokenProjectionSpec::default()).unwrap();
        let good_pod = PodSpec {
            containers: vec![Container {
                name: "runner".to_owned(),
                env: Some(vec![
                    EnvVar {
                        name: "RUST_LOG".to_owned(),
                        value: Some("info".to_owned()),
                        ..Default::default()
                    },
                    EnvVar {
                        name: "OPENBAO_TOKEN".to_owned(),
                        value_from: Some(EnvVarSource {
                            secret_key_ref: Some(SecretKeySelector {
                                name: "bao-creds-a1b2c3d4".to_owned(),
                                key: "token".to_owned(),
                                optional: Some(false),
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ]),
                volume_mounts: Some(vec![mount]),
                ..Default::default()
            }],
            volumes: Some(vec![vol]),
            ..Default::default()
        };
        assert!(audit_pod_secret_and_token_hygiene(&good_pod).is_ok());

        let bad_pod = PodSpec {
            containers: vec![Container {
                name: "runner".to_owned(),
                env: Some(vec![EnvVar {
                    name: "LITELLM_API_KEY".to_owned(),
                    value: Some("sk-plaintext-leak".to_owned()),
                    ..Default::default()
                }]),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(matches!(
            audit_pod_secret_and_token_hygiene(&bad_pod),
            Err(SecretHygieneError::PlaintextSensitiveEnvVar { .. })
        ));
    }
}
