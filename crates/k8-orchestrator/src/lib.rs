// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `k8-orchestrator`: Engine for scheduling, sandboxing, and reaping agent workloads.

use k8_api::AgentWorkloadSpec;
use k8_core::{K8Client, Result};
use k8s_openapi::api::batch::v1::{Job, JobSpec};
use k8s_openapi::api::core::v1::{
    Container, EnvVar, PodSecurityContext, PodSpec, PodTemplateSpec, ResourceRequirements,
    SecurityContext,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, DeleteParams, PostParams};
use std::collections::BTreeMap;
use tracing::info;
use uuid::Uuid;

/// Orchestrator service managing agent execution on a Kubernetes cluster.
#[derive(Clone)]
pub struct Orchestrator {
    client: K8Client,
}

impl Orchestrator {
    pub fn new(client: K8Client) -> Self {
        Self { client }
    }

    /// Construct a Kubernetes Job definition from an AgentWorkloadSpec without I/O.
    pub fn build_job(run_id: &str, namespace: &str, spec: &AgentWorkloadSpec) -> Job {
        let mut labels = BTreeMap::new();
        labels.insert("app.kubernetes.io/name".to_string(), "k8-agent".to_string());
        labels.insert("app.kubernetes.io/managed-by".to_string(), "k8".to_string());
        labels.insert("unsigned.gg/run-id".to_string(), run_id.to_string());
        if let Some(role) = &spec.agent_role {
            labels.insert("unsigned.gg/agent-role".to_string(), role.clone());
        }

        let env_vars = spec
            .env
            .iter()
            .map(|(k, v)| EnvVar {
                name: k.clone(),
                value: Some(v.clone()),
                ..Default::default()
            })
            .collect();

        let mut limits = BTreeMap::new();
        if let Some(cpu) = &spec.cpu {
            limits.insert("cpu".to_string(), Quantity(cpu.clone()));
        }
        if let Some(mem) = &spec.memory {
            limits.insert("memory".to_string(), Quantity(mem.clone()));
        }
        if let Some(gpu) = spec.gpu {
            limits.insert("nvidia.com/gpu".to_string(), Quantity(gpu.to_string()));
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
            env: Some(env_vars),
            resources: Some(ResourceRequirements {
                limits: Some(limits.clone()),
                requests: Some(limits),
                ..Default::default()
            }),
            security_context: Some(SecurityContext {
                allow_privilege_escalation: Some(false),
                read_only_root_filesystem: Some(false),
                run_as_non_root: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        let pod_spec = PodSpec {
            restart_policy: Some("Never".to_string()),
            containers: vec![container],
            security_context: Some(PodSecurityContext {
                run_as_non_root: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        Job {
            metadata: ObjectMeta {
                name: Some(run_id.to_string()),
                namespace: Some(namespace.to_string()),
                labels: Some(labels.clone()),
                ..Default::default()
            },
            spec: Some(JobSpec {
                backoff_limit: Some(0),
                active_deadline_seconds: spec.timeout_seconds.map(|s| s as i64),
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
        }
    }

    /// Dispatch a new agent job onto the cluster using strict sandbox isolation.
    pub async fn dispatch(&self, spec: AgentWorkloadSpec) -> Result<String> {
        let run_id = format!("agent-{}", &Uuid::new_v4().to_string()[..8]);
        let jobs: Api<Job> = Api::namespaced(self.client.inner().clone(), self.client.namespace());
        let job = Self::build_job(&run_id, self.client.namespace(), &spec);

        info!(run_id = %run_id, "Dispatching agent Job to Kubernetes cluster");
        jobs.create(&PostParams::default(), &job).await?;
        Ok(run_id)
    }

    /// Terminate and remove an agent Job.
    pub async fn terminate(&self, run_id: &str) -> Result<()> {
        let jobs: Api<Job> = Api::namespaced(self.client.inner().clone(), self.client.namespace());
        info!(run_id = %run_id, "Deleting agent Job");
        let dp = DeleteParams::default();
        jobs.delete(run_id, &dp).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_job_invariants() {
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

        let job = Orchestrator::build_job("agent-test1234", "agent-ns", &spec);

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

        let pod_spec = job_spec.template.spec.expect("pod spec present");
        assert_eq!(pod_spec.restart_policy, Some("Never".to_string()));
        assert_eq!(
            pod_spec.security_context.and_then(|sc| sc.run_as_non_root),
            Some(true)
        );

        let container = &pod_spec.containers[0];
        assert_eq!(container.name, "agent");
        assert_eq!(
            container.image,
            Some("ghcr.io/unsigned-gg/agent:latest".to_string())
        );
        assert_eq!(container.command, Some(vec!["agent".to_string()]));
        assert_eq!(
            container.args,
            Some(vec!["solve".to_string(), "CER-42".to_string()])
        );

        let sec = container
            .security_context
            .as_ref()
            .expect("security context present");
        assert_eq!(sec.run_as_non_root, Some(true));
        assert_eq!(sec.allow_privilege_escalation, Some(false));
    }
}
