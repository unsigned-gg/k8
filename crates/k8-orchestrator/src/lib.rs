// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `k8-orchestrator`: Engine for scheduling, PodSecurity `restricted` sandboxing, and reconciling
//! autonomous agent workloads on Kubernetes.

pub mod reconciler;

pub use reconciler::{
    reconcile_workload_pure, ReconcileEffect, ReconcileObservation, ReconcilePlan,
};

use k8_api::{
    audit_pod_spec_restricted, audit_pod_volumes, build_dedicated_service_account,
    build_isolated_network_policy, build_scoped_role, build_scoped_role_binding,
    build_scratch_volume_and_mount, build_workload_pdb, build_workload_tolerations,
    canonical_workload_labels, ensure_cleanup_finalizer, remove_cleanup_finalizer,
    restricted_container_security_context, restricted_pod_security_context, to_yaml_manifest,
    AgentWorkload, AgentWorkloadSpec, ScratchVolumeSpec, WorkloadPhase, LABEL_MANAGED_BY,
};
use k8_core::{delete_foreground_params, list_by_selector, K8Client, K8Error, Result};
use k8s_openapi::api::batch::v1::{Job, JobSpec};
use k8s_openapi::api::core::v1::{
    Container, EnvVar, PodSpec, PodTemplateSpec, ResourceRequirements,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
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
        Self::build_validated_job_with_owner(run_id, namespace, spec, None)
    }

    /// Validate `spec` and construct a PodSecurity `restricted` Kubernetes [`Job`] with an optional
    /// controller [`OwnerReference`], Kata microVM `runtimeClassName`, node taint tolerations,
    /// dedicated `ServiceAccount`, and bounded ephemeral scratch volumes.
    pub fn build_validated_job_with_owner(
        run_id: &str,
        namespace: &str,
        spec: &AgentWorkloadSpec,
        owner_ref: Option<OwnerReference>,
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

        let scratch_specs: Vec<ScratchVolumeSpec> = if spec.scratch_volumes.is_empty() {
            vec![ScratchVolumeSpec::default()]
        } else {
            spec.scratch_volumes.clone()
        };

        let mut volumes = Vec::with_capacity(scratch_specs.len());
        let mut volume_mounts = Vec::with_capacity(scratch_specs.len());
        for scratch in &scratch_specs {
            let (vol, mount) = build_scratch_volume_and_mount(scratch)
                .map_err(k8_api::SpecValidationError::from)?;
            volumes.push(vol);
            volume_mounts.push(mount);
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
            volume_mounts: Some(volume_mounts),
            security_context: Some(restricted_container_security_context()),
            ..Default::default()
        };

        let tolerations = build_workload_tolerations(req.gpu, true);
        let runtime_class_name = spec
            .isolation_profile
            .runtime_class_name()
            .map(str::to_string);

        let pod_spec = PodSpec {
            service_account_name: Some(format!("{run_id}-sa")),
            automount_service_account_token: Some(false),
            restart_policy: Some("Never".to_string()),
            runtime_class_name,
            tolerations: if tolerations.is_empty() {
                None
            } else {
                Some(tolerations)
            },
            volumes: Some(volumes),
            containers: vec![container],
            security_context: Some(restricted_pod_security_context()),
            ..Default::default()
        };

        audit_pod_spec_restricted(&pod_spec).map_err(K8Error::SecurityAudit)?;
        audit_pod_volumes(&pod_spec).map_err(k8_api::SpecValidationError::from)?;

        let active_deadline = spec.timeout_seconds.and_then(|s| i64::try_from(s).ok());

        Ok(Job {
            metadata: ObjectMeta {
                name: Some(run_id.to_string()),
                namespace: Some(namespace.to_string()),
                labels: Some(labels.clone()),
                owner_references: owner_ref.map(|o| vec![o]),
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

    /// Validate `spec` and render a full zero-trust Kubernetes YAML 1.2 bundle containing
    /// `ServiceAccount` (+ optional `Role` and `RoleBinding`), `NetworkPolicy`,
    /// `PodDisruptionBudget`, and `Job` separated by `---`.
    pub fn render_workload_bundle_yaml(
        run_id: &str,
        namespace: &str,
        spec: &AgentWorkloadSpec,
    ) -> Result<String> {
        let job = Self::build_validated_job(run_id, namespace, spec)?;
        let labels = canonical_workload_labels(run_id, spec.agent_role.as_deref())
            .map_err(k8_api::SpecValidationError::from)?;
        let sa = build_dedicated_service_account(run_id, namespace, labels.clone(), false)
            .map_err(k8_api::SpecValidationError::from)?;
        let netpol = build_isolated_network_policy(
            run_id,
            namespace,
            spec.agent_role.as_deref(),
            spec.egress.as_ref(),
        )
        .map_err(k8_api::SpecValidationError::from)?;
        let pdb = build_workload_pdb(run_id, namespace, spec.agent_role.as_deref(), 1)
            .map_err(k8_api::SpecValidationError::from)?;

        let mut docs = Vec::with_capacity(6);
        docs.push(to_yaml_manifest(&sa)?.trim_end().to_owned());
        if !spec.rbac_rules.is_empty() {
            let role = build_scoped_role(run_id, namespace, labels.clone(), &spec.rbac_rules)
                .map_err(k8_api::SpecValidationError::from)?;
            let rb = build_scoped_role_binding(run_id, namespace, labels)
                .map_err(k8_api::SpecValidationError::from)?;
            docs.push(to_yaml_manifest(&role)?.trim_end().to_owned());
            docs.push(to_yaml_manifest(&rb)?.trim_end().to_owned());
        }
        docs.push(to_yaml_manifest(&netpol)?.trim_end().to_owned());
        docs.push(to_yaml_manifest(&pdb)?.trim_end().to_owned());
        docs.push(to_yaml_manifest(&job)?);

        Ok(docs.join("\n---\n"))
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

    /// Execute a pure [`ReconcilePlan`] against the Kubernetes API server via Server-Side Apply.
    pub async fn execute_reconcile_plan(
        &self,
        workload: &AgentWorkload,
        plan: &ReconcilePlan,
    ) -> Result<()> {
        let name = workload
            .metadata
            .name
            .as_deref()
            .ok_or_else(|| K8Error::Config("AgentWorkload metadata.name is required".into()))?;

        for effect in &plan.effects {
            match effect {
                ReconcileEffect::EnsureFinalizer => {
                    let mut patched = workload.clone();
                    if ensure_cleanup_finalizer(&mut patched.metadata) {
                        self.client.apply_namespaced(name, &patched, true).await?;
                    }
                }
                ReconcileEffect::ApplyNetworkPolicy(netpol) => {
                    let netpol_name = netpol
                        .metadata
                        .name
                        .as_deref()
                        .ok_or_else(|| K8Error::Config("NetworkPolicy name missing".into()))?;
                    self.client
                        .apply_namespaced(netpol_name, netpol.as_ref(), true)
                        .await?;
                }
                ReconcileEffect::ApplyChildJob(job) => {
                    let job_name = job
                        .metadata
                        .name
                        .as_deref()
                        .ok_or_else(|| K8Error::Config("Job name missing".into()))?;
                    self.client
                        .apply_namespaced(job_name, job.as_ref(), true)
                        .await?;
                }
                ReconcileEffect::DeleteChildJob(run_id) => {
                    self.terminate(run_id).await?;
                }
                ReconcileEffect::PatchWorkloadStatus(status) => {
                    let mut patched = workload.clone();
                    patched.status = Some(status.clone());
                    self.client.patch_status_namespaced(name, &patched).await?;
                }
                ReconcileEffect::RemoveFinalizer => {
                    let mut patched = workload.clone();
                    if remove_cleanup_finalizer(&mut patched.metadata) {
                        self.client.apply_namespaced(name, &patched, true).await?;
                    }
                }
            }
        }
        Ok(())
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
    use k8_api::{from_multi_yaml_manifests, EgressRuleSpec, IsolationProfile, ManifestHeader};
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
            isolation_profile: IsolationProfile::KataMicroVm,
            egress: Some(EgressRuleSpec {
                allow_dns: true,
                allowed_cidrs: vec!["10.42.0.0/16".to_string()],
                allowed_tcp_ports: vec![443],
            }),
            ..Default::default()
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
        assert_eq!(
            pod_spec.service_account_name.as_deref(),
            Some("agent-test1234-sa")
        );
        assert_eq!(pod_spec.runtime_class_name.as_deref(), Some("kata"));
        assert_eq!(pod_spec.tolerations.as_ref().map(Vec::len), Some(2));
        assert!(audit_pod_spec_restricted(&pod_spec).is_ok());

        let yaml = Orchestrator::render_job_yaml("agent-test1234", "agent-ns", &spec)
            .expect("render job yaml");
        assert!(yaml.contains("agent-test1234"));
        assert!(yaml.contains("RuntimeDefault"));

        let bundle = Orchestrator::render_workload_bundle_yaml("agent-test1234", "agent-ns", &spec)
            .expect("render bundle yaml");
        let headers: Vec<ManifestHeader> =
            from_multi_yaml_manifests(&bundle).expect("parse multi-doc bundle");
        assert_eq!(headers.len(), 4);
        assert_eq!(headers[0].kind, "ServiceAccount");
        assert_eq!(headers[1].kind, "NetworkPolicy");
        assert_eq!(headers[2].kind, "PodDisruptionBudget");
        assert_eq!(headers[3].kind, "Job");
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
