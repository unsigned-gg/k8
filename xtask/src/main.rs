//! Repo automation for `k8`. Run with `cargo xtask <command>`.
//!
//! Commands:
//! - `check`: run the checkpointed verification DAG (`--resume`, `--enforce-dbr`, `--break-check`).
//! - `graph-audit`: verify the workspace dependency DAG and Wave-0 zero-I/O leaf crate (`--break-check`).
//! - `zero-io-domain`: alias for `graph-audit` verifying Wave-0 zero-I/O invariants on `k8-api`.
//! - `spec-check`: validate architecture specifications under `specs/`.
//! - `toolchain-check`: verify active `rustc` matches `rust-toolchain.toml` and MSRV floor.
//! - `branch-hygiene`: audit or prune merged local branches (`--dry-run` default, `--apply`).

mod branch_hygiene;
mod graph_audit;
mod pipeline;
mod spec_check;
mod toolchain;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Return the repository root directory (parent of `xtask`).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn main() -> ExitCode {
    let arg = std::env::args().nth(1);
    let root = repo_root();
    match arg.as_deref() {
        Some("check") => {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            pipeline::run(&root, &rest)
        }
        Some("graph-audit" | "zero-io-domain") => {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            graph_audit::run(&root, &rest)
        }
        Some("spec-check") => spec_check::run(&root),
        Some("toolchain-check") => toolchain::run(&root),
        Some("branch-hygiene") => branch_hygiene::run(&root),
        other => {
            if let Some(name) = other {
                eprintln!("xtask: unknown command {name:?}");
            }
            eprintln!(
                "usage: cargo xtask <check|graph-audit|zero-io-domain|spec-check|toolchain-check|branch-hygiene>"
            );
            ExitCode::from(2)
        }
    }
}
