// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `k8-orchestrator`: Engine for scheduling, PodSecurity `restricted` sandboxing, and reconciling
//! autonomous agent workloads on Kubernetes.

use k8_api::{
    audit_pod_spec_restricted, canonical_workload_labels, restricted_container_security_context,
    restricted_pod_security_context, to_yaml_manifest, AgentWorkload, AgentWorkloadSpec,
    WorkloadPhase, LABEL_MANAGED_BY,
};
use k8_core::{delete_foreground_params, list_by_selector, K8Client, K8Error, Result};
use k8s_openapi::api::batch::v1::{Job, JobSpec};
use k8s_openapi::api::core::v1::{
    Container, EnvVar, PodSpec, PodTemplateSpec, ResourceRequirements,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::Api;
use std::collections::BTreeMap;
use tracing::info;
use uuid::Uuid;

/// Default TTL in seconds after a Job finishes before Kubernetes garbage-collects it.
pub const DEFAULT_TTL_SECONDS_AFTER_FINISHED: i32 = 3_600;

/// Orchestrator service managing agent execution on a Kubernetes cluster.
#[derive(Clone)]
pub struct Orchestrator {
    client: K8Client,
}

impl Orchestrator {
    /// Construct a new [`Orchestrator`] bound to `client`.
    #[must_use]
    pub fn new(client: K8Client) -> Self {
        Self { client }
    }

    /// Return a reference to the underlying [`K8Client`].
    #[must_use]
    pub fn client(&self) -> &K8Client {
        &self.client
    }

    /// Validate `spec` and construct a PodSecurity `restricted` Kubernetes [`Job`] without I/O.
    pub fn build_validated_job(
        run_id: &str,
        namespace: &str,
        spec: &AgentWorkloadSpec,
    ) -> Result<Job> {
        let req = spec.validate()?;
        let labels = canonical_workload_labels(run_id, spec.agent_role.as_deref())
            .map_err(k8_api::SpecValidationError::from)?;

        let env_vars: Vec<EnvVar> = spec
            .env
            .iter()
            .map(|(k, v)| EnvVar {
                name: k.clone(),
                value: Some(v.clone()),
                ..Default::default()
            })
            .collect();

        let mut limits = BTreeMap::new();
        limits.insert("cpu".to_string(), req.cpu.to_k8s_quantity());
        limits.insert("memory".to_string(), req.memory.to_k8s_quantity());
        if req.gpu > 0 {
            limits.insert("nvidia.com/gpu".to_string(), Quantity(req.gpu.to_string()));
        }

        let container = Container {
            name: "agent".to_string(),
            image: Some(spec.image.clone()),
            command: if spec.command.is_empty() {
                None
            } else {
                Some(spec.command.clone())
            },
            args: if spec.args.is_empty() {
                None
            } else {
                Some(spec.args.clone())
            },
            env: if env_vars.is_empty() {
                None
            } else {
                Some(env_vars)
            },
            resources: Some(ResourceRequirements {
                limits: Some(limits.clone()),
                requests: Some(limits),
                ..Default::default()
            }),
            security_context: Some(restricted_container_security_context()),
            ..Default::default()
        };

        let pod_spec = PodSpec {
            automount_service_account_token: Some(false),
            restart_policy: Some("Never".to_string()),
            containers: vec![container],
            security_context: Some(restricted_pod_security_context()),
            ..Default::default()
        };

        audit_pod_spec_restricted(&pod_spec).map_err(K8Error::SecurityAudit)?;

        let active_deadline = spec.timeout_seconds.and_then(|s| i64::try_from(s).ok());

        Ok(Job {
            metadata: ObjectMeta {
                name: Some(run_id.to_string()),
                namespace: Some(namespace.to_string()),
                labels: Some(labels.clone()),
                ..Default::default()
            },
            spec: Some(JobSpec {
                backoff_limit: Some(0),
                active_deadline_seconds: active_deadline,
                ttl_seconds_after_finished: Some(DEFAULT_TTL_SECONDS_AFTER_FINISHED),
                template: PodTemplateSpec {
                    metadata: Some(ObjectMeta {
                        labels: Some(labels),
                        ..Default::default()
                    }),
                    spec: Some(pod_spec),
                },
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    /// Construct a Kubernetes [`Job`] definition from an [`AgentWorkloadSpec`] without I/O.
    #[must_use]
    pub fn build_job(run_id: &str, namespace: &str, spec: &AgentWorkloadSpec) -> Job {
        if let Ok(job) = Self::build_validated_job(run_id, namespace, spec) {
            return job;
        }
        Job::default()
    }

    /// Validate `spec` and render the hardened Kubernetes [`Job`] as a YAML 1.2 manifest.
    pub fn render_job_yaml(
        run_id: &str,
        namespace: &str,
        spec: &AgentWorkloadSpec,
    ) -> Result<String> {
        let job = Self::build_validated_job(run_id, namespace, spec)?;
        Ok(to_yaml_manifest(&job)?)
    }

    /// Deterministically evaluate the [`WorkloadPhase`] of a Kubernetes [`Job`].
    #[must_use]
    pub fn evaluate_job_phase(job: &Job) -> WorkloadPhase {
        let Some(status) = &job.status else {
            return WorkloadPhase::Pending;
        };
        if status.succeeded.unwrap_or(0) > 0 {
            WorkloadPhase::Succeeded
        } else if status.failed.unwrap_or(0) > 0 {
            WorkloadPhase::Failed
        } else if status.active.unwrap_or(0) > 0 {
            WorkloadPhase::Running
        } else {
            WorkloadPhase::Pending
        }
    }

    /// Server-Side Apply an [`AgentWorkload`] custom resource onto the cluster.
    pub async fn apply_workload(&self, workload: &AgentWorkload) -> Result<AgentWorkload> {
        workload.spec.validate()?;
        let name = workload
            .metadata
            .name
            .as_deref()
            .ok_or_else(|| K8Error::Config("AgentWorkload metadata.name is required".into()))?;
        self.client.apply_namespaced(name, workload, true).await
    }

    /// Dispatch a new agent [`Job`] onto the cluster using Server-Side Apply and PodSecurity `restricted` isolation.
    pub async fn dispatch(&self, spec: AgentWorkloadSpec) -> Result<String> {
        let raw_uuid = Uuid::new_v4().simple().to_string();
        let short_id = raw_uuid.get(..8).unwrap_or("00000000");
        let run_id = format!("agent-{short_id}");
        let job = Self::build_validated_job(&run_id, self.client.namespace(), &spec)?;

        info!(run_id = %run_id, "Applying sandboxed agent Job via Server-Side Apply");
        self.client.apply_namespaced(&run_id, &job, true).await?;
        Ok(run_id)
    }

    /// Reconcile all managed agent [`Job`] resources in the active namespace and return their phases.
    pub async fn reconcile_once(&self) -> Result<Vec<(String, WorkloadPhase)>> {
        let jobs: Api<Job> = Api::namespaced(self.client.inner().clone(), self.client.namespace());
        let selector = format!("{LABEL_MANAGED_BY}=k8");
        let job_list = jobs.list(&list_by_selector(&selector)).await?;

        let mut report = Vec::with_capacity(job_list.items.len());
        for job in &job_list.items {
            let name = job.metadata.name.clone().unwrap_or_default();
            let phase = Self::evaluate_job_phase(job);
            report.push((name, phase));
        }
        Ok(report)
    }

    /// Terminate and remove an agent [`Job`] with foreground cascading deletion.
    pub async fn terminate(&self, run_id: &str) -> Result<()> {
        let jobs: Api<Job> = Api::namespaced(self.client.inner().clone(), self.client.namespace());
        info!(run_id = %run_id, "Deleting agent Job with foreground propagation");
        let dp = delete_foreground_params();
        jobs.delete(run_id, &dp).await?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use k8s_openapi::api::batch::v1::JobStatus;

    #[test]
    fn test_build_validated_job_invariants_and_yaml_render() {
        let mut env = BTreeMap::new();
        env.insert("MODE".to_string(), "autonomous".to_string());

        let spec = AgentWorkloadSpec {
            image: "ghcr.io/unsigned-gg/agent:latest".to_string(),
            command: vec!["agent".to_string()],
            args: vec!["solve".to_string(), "CER-42".to_string()],
            env,
            cpu: Some("2000m".to_string()),
            memory: Some("4Gi".to_string()),
            gpu: Some(1),
            timeout_seconds: Some(3600),
            agent_role: Some("researcher".to_string()),
        };

        let job = Orchestrator::build_validated_job("agent-test1234", "agent-ns", &spec)
            .expect("valid job");

        assert_eq!(job.metadata.name, Some("agent-test1234".to_string()));
        assert_eq!(job.metadata.namespace, Some("agent-ns".to_string()));

        let labels = job.metadata.labels.expect("labels present");
        assert_eq!(
            labels.get("unsigned.gg/run-id"),
            Some(&"agent-test1234".to_string())
        );
        assert_eq!(
            labels.get("unsigned.gg/agent-role"),
            Some(&"researcher".to_string())
        );
        assert_eq!(
            labels.get("app.kubernetes.io/managed-by"),
            Some(&"k8".to_string())
        );

        let job_spec = job.spec.expect("job spec present");
        assert_eq!(job_spec.backoff_limit, Some(0));
        assert_eq!(job_spec.active_deadline_seconds, Some(3600));
        assert_eq!(
            job_spec.ttl_seconds_after_finished,
            Some(DEFAULT_TTL_SECONDS_AFTER_FINISHED)
        );

        let pod_spec = job_spec.template.spec.expect("pod spec present");
        assert_eq!(pod_spec.automount_service_account_token, Some(false));
        assert!(audit_pod_spec_restricted(&pod_spec).is_ok());

        let yaml = Orchestrator::render_job_yaml("agent-test1234", "agent-ns", &spec)
            .expect("render job yaml");
        assert!(yaml.contains("agent-test1234"));
        assert!(yaml.contains("RuntimeDefault"));
    }

    #[test]
    fn test_evaluate_job_phase() {
        let mut job = Job::default();
        assert_eq!(
            Orchestrator::evaluate_job_phase(&job),
            WorkloadPhase::Pending
        );

        job.status = Some(JobStatus {
            active: Some(1),
            ..Default::default()
        });
        assert_eq!(
            Orchestrator::evaluate_job_phase(&job),
            WorkloadPhase::Running
        );

        job.status = Some(JobStatus {
            succeeded: Some(1),
            ..Default::default()
        });
        assert_eq!(
            Orchestrator::evaluate_job_phase(&job),
            WorkloadPhase::Succeeded
        );

        job.status = Some(JobStatus {
            failed: Some(1),
            ..Default::default()
        });
        assert_eq!(
            Orchestrator::evaluate_job_phase(&job),
            WorkloadPhase::Failed
        );
    }
}
