//! `cargo xtask graph-audit`: Dependency Matrix & Tear-Free Workspace DAG Auditor for `k8`.
//!
//! Enforces:
//! 1. **Acyclic Workspace DAG (Kahn's Algorithm / Tarjan SCCs)**:
//!    Constructs the internal workspace dependency adjacency matrix across `crates/*`
//!    and verifies that the dependency graph contains zero cycles (every SCC has size 1).
//! 2. **Wave-0 Pure Leaf Verification (`k8-api`)**:
//!    Verifies that `k8-api` sits in topological Wave 0 (`in_degree == 0` internal workspace
//!    dependencies) and contains zero runtime I/O symbols (`std::net`, `std::fs`, `std::process`,
//!    `tokio::`).
//! 3. **Falsifiable Mutation Self-Test (`--break-check`)**:
//!    Injects a synthetic circular dependency (`k8-api -> k8-core -> k8-api`) and an
//!    forbidden I/O symbol into a virtual graph to prove the auditor fails closed.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::Path;
use std::process::ExitCode;

/// Forbidden I/O and async runtime prefixes inside the Wave-0 `k8-api` crate.
const FORBIDDEN_WAVE0_IO_SYMBOLS: &[&str] = &["std::net", "std::fs", "std::process", "tokio::"];

/// Internal workspace crate node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateNode {
    /// Crate package name.
    pub name: String,
    /// Relative manifest path.
    pub manifest_path: String,
    /// Internal workspace crates that this crate depends on.
    pub internal_deps: BTreeSet<String>,
    /// Forbidden I/O symbols detected in source files (if Wave-0 leaf crate).
    pub forbidden_io_hits: Vec<String>,
}

/// Audit report for the workspace dependency graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphAuditReport {
    /// Ordered topological waves (`Wave 0` = pure leaf crates, `Wave 1` = next layer, etc.).
    pub waves: Vec<Vec<String>>,
    /// Any cycles or invariant violations discovered.
    pub errors: Vec<String>,
}

/// CLI entry point for `cargo xtask graph-audit`.
pub fn run(root: &Path, args: &[String]) -> ExitCode {
    let break_check = args.iter().any(|a| a == "--break-check");
    if break_check {
        return run_break_check();
    }

    match inspect_workspace(root) {
        Ok(nodes) => {
            let report = audit_graph(&nodes);
            for (idx, wave) in report.waves.iter().enumerate() {
                println!("graph-audit: wave {idx}: {}", wave.join(", "));
            }
            for err in &report.errors {
                eprintln!("graph-audit error: {err}");
            }
            if report.errors.is_empty() {
                println!(
                    "graph-audit: ok ({} crates across {} topological waves, 0 cycles, Wave-0 k8-api pure)",
                    nodes.len(),
                    report.waves.len()
                );
                ExitCode::SUCCESS
            } else {
                eprintln!("graph-audit: FAILED ({} error(s))", report.errors.len());
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("graph-audit: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Falsifiable self-test (`--break-check`): prove the auditor catches both cycles and Wave-0 I/O leaks.
fn run_break_check() -> ExitCode {
    let mut cyclic_nodes = BTreeMap::new();
    cyclic_nodes.insert(
        "k8-api".to_string(),
        CrateNode {
            name: "k8-api".to_string(),
            manifest_path: "crates/k8-api/Cargo.toml".to_string(),
            internal_deps: BTreeSet::from(["k8-core".to_string()]),
            forbidden_io_hits: vec!["crates/k8-api/src/lib.rs:10: std::fs::File::open".to_string()],
        },
    );
    cyclic_nodes.insert(
        "k8-core".to_string(),
        CrateNode {
            name: "k8-core".to_string(),
            manifest_path: "crates/k8-core/Cargo.toml".to_string(),
            internal_deps: BTreeSet::from(["k8-api".to_string()]),
            forbidden_io_hits: Vec::new(),
        },
    );

    let report = audit_graph(&cyclic_nodes);
    let caught_cycle = report.errors.iter().any(|e| e.contains("cycle detected"));
    let caught_wave0 = report
        .errors
        .iter()
        .any(|e| e.contains("Wave-0 leaf crate `k8-api`"));

    if caught_cycle && caught_wave0 {
        println!(
            "graph-audit --break-check: ok (caught synthetic cycle and Wave-0 I/O leak: {} errors)",
            report.errors.len()
        );
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "graph-audit --break-check: FAILED to catch synthetic faults: {:?}",
            report.errors
        );
        ExitCode::FAILURE
    }
}

/// Inspect `<root>/crates/*` and construct the internal workspace dependency map.
pub fn inspect_workspace(root: &Path) -> Result<BTreeMap<String, CrateNode>, String> {
    let crates_dir = root.join("crates");
    let entries = fs::read_dir(&crates_dir)
        .map_err(|e| format!("cannot read {}: {e}", crates_dir.display()))?;

    let mut raw_manifests: BTreeMap<String, (String, String)> = BTreeMap::new();
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest = path.join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        let content = fs::read_to_string(&manifest)
            .map_err(|e| format!("cannot read {}: {e}", manifest.display()))?;
        if let Some(pkg_name) = parse_package_name(&content) {
            let rel = format!(
                "crates/{}/Cargo.toml",
                path.file_name().unwrap_or_default().to_string_lossy()
            );
            raw_manifests.insert(pkg_name, (rel, content));
        }
    }

    let known_crates: BTreeSet<String> = raw_manifests.keys().cloned().collect();
    let mut nodes = BTreeMap::new();

    for (name, (rel_manifest, content)) in &raw_manifests {
        let deps = parse_internal_deps(content, &known_crates);
        let mut forbidden_io_hits = Vec::new();
        if name == "k8-api" {
            let src_dir = root.join("crates/k8-api/src");
            scan_for_forbidden_io(&src_dir, "crates/k8-api/src", &mut forbidden_io_hits)?;
        }
        nodes.insert(
            name.clone(),
            CrateNode {
                name: name.clone(),
                manifest_path: rel_manifest.clone(),
                internal_deps: deps,
                forbidden_io_hits,
            },
        );
    }

    Ok(nodes)
}

/// Audit a workspace crate graph for cycles (Kahn's algorithm) and Wave-0 purity.
pub fn audit_graph(nodes: &BTreeMap<String, CrateNode>) -> GraphAuditReport {
    let mut errors = Vec::new();

    if let Some(api) = nodes.get("k8-api") {
        if !api.internal_deps.is_empty() {
            errors.push(format!(
                "Wave-0 leaf crate `k8-api` must have 0 internal workspace dependencies, found: {:?}",
                api.internal_deps
            ));
        }
        for hit in &api.forbidden_io_hits {
            errors.push(format!(
                "Wave-0 leaf crate `k8-api` contains forbidden runtime I/O symbol at {hit}"
            ));
        }
    } else {
        errors.push("missing required Wave-0 leaf crate `k8-api`".to_string());
    }

    let mut in_degree: BTreeMap<String, usize> = BTreeMap::new();
    let mut dependents: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (name, node) in nodes {
        let valid_deps: Vec<&String> = node
            .internal_deps
            .iter()
            .filter(|d| nodes.contains_key(*d))
            .collect();
        in_degree.insert(name.clone(), valid_deps.len());
        for dep in valid_deps {
            dependents
                .entry(dep.clone())
                .or_default()
                .push(name.clone());
        }
    }

    let mut waves: Vec<Vec<String>> = Vec::new();
    let mut queue: VecDeque<String> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(k, _)| k.clone())
        .collect();

    let mut visited_count = 0usize;

    while !queue.is_empty() {
        let mut current_wave: Vec<String> = queue.drain(..).collect();
        current_wave.sort();
        visited_count += current_wave.len();

        let mut next_wave_candidates = Vec::new();
        for u in &current_wave {
            if let Some(children) = dependents.get(u) {
                for v in children {
                    if let Some(deg) = in_degree.get_mut(v) {
                        *deg -= 1;
                        if *deg == 0 {
                            next_wave_candidates.push(v.clone());
                        }
                    }
                }
            }
        }
        next_wave_candidates.sort();
        for c in next_wave_candidates {
            queue.push_back(c);
        }
        waves.push(current_wave);
    }

    if visited_count != nodes.len() {
        let stuck: Vec<String> = in_degree
            .into_iter()
            .filter(|(_, deg)| *deg > 0)
            .map(|(k, _)| k)
            .collect();
        errors.push(format!(
            "dependency cycle detected among workspace crates: {}",
            stuck.join(" <-> ")
        ));
    }

    if let Some(wave0) = waves.first() {
        if !wave0.iter().any(|c| c == "k8-api") {
            errors.push("`k8-api` did not resolve into topological Wave 0".to_string());
        }
    }

    GraphAuditReport { waves, errors }
}

fn parse_package_name(cargo_toml: &str) -> Option<String> {
    let mut in_pkg = false;
    for raw in cargo_toml.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_pkg = line == "[package]";
            continue;
        }
        if in_pkg {
            if let Some((k, v)) = line.split_once('=') {
                if k.trim() == "name" {
                    return Some(v.trim().trim_matches('"').to_string());
                }
            }
        }
    }
    None
}

fn parse_internal_deps(cargo_toml: &str, known_crates: &BTreeSet<String>) -> BTreeSet<String> {
    let mut deps = BTreeSet::new();
    let mut in_deps = false;
    for raw in cargo_toml.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            let section = line.trim_matches(|c| c == '[' || c == ']').trim();
            in_deps = section == "dependencies"
                || section == "dev-dependencies"
                || section == "build-dependencies";
            continue;
        }
        if in_deps {
            if let Some((k, _)) = line.split_once('=') {
                let key = k.trim();
                if known_crates.contains(key) {
                    deps.insert(key.to_string());
                }
            }
        }
    }
    deps
}

fn scan_for_forbidden_io(
    dir: &Path,
    rel_prefix: &str,
    hits: &mut Vec<String>,
) -> Result<(), String> {
    if !dir.is_dir() {
        return Ok(());
    }
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let file_name = entry.file_name().to_string_lossy().to_string();
        let rel_path = format!("{rel_prefix}/{file_name}");
        if path.is_dir() {
            scan_for_forbidden_io(&path, &rel_path, hits)?;
        } else if file_name.ends_with(".rs") {
            let content =
                fs::read_to_string(&path).map_err(|e| format!("cannot read {rel_path}: {e}"))?;
            for (idx, raw) in content.lines().enumerate() {
                let code_part = raw.split("//").next().unwrap_or("");
                for sym in FORBIDDEN_WAVE0_IO_SYMBOLS {
                    if code_part.contains(sym) {
                        hits.push(format!("{rel_path}:{}: {sym}", idx + 1));
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

    #[test]
    fn real_workspace_is_acyclic_and_k8_api_is_wave0() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let nodes = inspect_workspace(root).unwrap();
        let report = audit_graph(&nodes);
        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
        assert!(report.waves[0].contains(&"k8-api".to_string()));
    }

    #[test]
    fn detects_cycle_and_wave0_violation() {
        assert_eq!(run_break_check(), ExitCode::SUCCESS);
    }
}
