// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `k8` CLI entrypoint.

use clap::{Parser, Subcommand};
use k8_api::AgentWorkloadSpec;
use k8_core::{K8Client, Result};
use k8_orchestrator::Orchestrator;
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ListParams};
use std::collections::BTreeMap;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "k8")]
#[command(author = "unsigned.gg <engineering@unsigned.gg>")]
#[command(version = "0.1.0")]
#[command(about = "Kubernetes agent orchestrator and native CLI tooling for autonomous agent fleets", long_about = None)]
struct Cli {
    /// Kubernetes namespace override
    #[arg(short, long, env = "K8S_NAMESPACE")]
    namespace: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Inspect cluster health, connected namespace, and agent node status
    Status,

    /// Dispatch a one-shot autonomous agent container Job
    Run {
        /// Container image to launch
        image: String,

        /// Command override
        #[arg(short, long, num_args = 1..)]
        command: Vec<String>,

        /// Arguments passed to the command
        #[arg(short, long, num_args = 1..)]
        args: Vec<String>,

        /// GPU count requested
        #[arg(short, long)]
        gpu: Option<u32>,

        /// CPU request/limit (e.g. 2000m or 2)
        #[arg(long)]
        cpu: Option<String>,

        /// Memory request/limit (e.g. 4Gi)
        #[arg(short, long)]
        memory: Option<String>,

        /// Job deadline in seconds
        #[arg(short, long)]
        timeout: Option<u64>,

        /// Agent persona or role label
        #[arg(short, long)]
        role: Option<String>,
    },

    /// List active agent workloads and Jobs
    List,

    /// Terminate and cleanup an agent Job
    Stop {
        /// Job run ID to terminate
        run_id: String,
    },

    /// Start the autonomous background orchestrator daemon loop
    Daemon,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "k8=info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();
    let mut client = K8Client::default_client().await?;
    if let Some(ns) = cli.namespace {
        client = client.with_namespace(ns);
    }

    match cli.command {
        Commands::Status => {
            println!("k8 Kubernetes Orchestrator v0.1.0");
            println!("Connected namespace: {}", client.namespace());
            let pods: Api<Pod> = Api::namespaced(client.inner().clone(), client.namespace());
            let lp = ListParams::default().labels("app.kubernetes.io/managed-by=k8");
            let pod_list = pods.list(&lp).await?;
            println!("Active agent pods: {}", pod_list.items.len());
        }

        Commands::Run {
            image,
            command,
            args,
            gpu,
            cpu,
            memory,
            timeout,
            role,
        } => {
            let orch = Orchestrator::new(client);
            let spec = AgentWorkloadSpec {
                image,
                command,
                args,
                env: BTreeMap::new(),
                cpu,
                memory,
                gpu,
                timeout_seconds: timeout,
                agent_role: role,
            };
            let run_id = orch.dispatch(spec).await?;
            println!("Dispatched agent Job: {}", run_id);
        }

        Commands::List => {
            let jobs: Api<Job> = Api::namespaced(client.inner().clone(), client.namespace());
            let lp = ListParams::default().labels("app.kubernetes.io/managed-by=k8");
            let job_list = jobs.list(&lp).await?;
            println!("{:<24} {:<15} {:<10}", "RUN ID", "STATUS", "COMPLETIONS");
            println!("{:-<52}", "");
            for job in job_list.items {
                let name = job.metadata.name.unwrap_or_default();
                let status = if let Some(s) = job.status {
                    if s.succeeded.unwrap_or(0) > 0 {
                        "Succeeded"
                    } else if s.failed.unwrap_or(0) > 0 {
                        "Failed"
                    } else if s.active.unwrap_or(0) > 0 {
                        "Running"
                    } else {
                        "Pending"
                    }
                } else {
                    "Unknown"
                };
                println!("{:<24} {:<15} {:<10}", name, status, "");
            }
        }

        Commands::Stop { run_id } => {
            let orch = Orchestrator::new(client);
            orch.terminate(&run_id).await?;
            println!("Terminated agent Job: {}", run_id);
        }

        Commands::Daemon => {
            println!("Starting k8 agent orchestrator daemon in namespace: {}", client.namespace());
            println!("Listening for autonomous agent workload CRDs and job signals...");
            tokio::signal::ctrl_c().await.expect("failed to listen for event");
            println!("Received shutdown signal. Exiting k8 daemon.");
        }
    }

    Ok(())
}
