//! `cargo xtask toolchain-check`.
//!
//! Verifies that the active `rustc` matches the `channel` in `rust-toolchain.toml`
//! and that `[workspace.package] rust-version` does not exceed that channel.

use std::fs;
use std::path::Path;
use std::process::{Command, ExitCode};

/// CLI entry point for `cargo xtask toolchain-check`.
pub fn run(root: &Path) -> ExitCode {
    match check(root) {
        Ok(msg) => {
            println!("toolchain-check: {msg}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("toolchain-check: {err}");
            ExitCode::FAILURE
        }
    }
}

fn check(root: &Path) -> Result<String, String> {
    let toolchain = fs::read_to_string(root.join("rust-toolchain.toml"))
        .map_err(|e| format!("cannot read rust-toolchain.toml: {e}"))?;
    let manifest = fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|e| format!("cannot read Cargo.toml: {e}"))?;
    let channel = toml_string(&toolchain, Some("toolchain"), "channel")
        .ok_or_else(|| "no `channel` in rust-toolchain.toml".to_string())?;
    let rust_version = toml_string(&manifest, Some("workspace.package"), "rust-version")
        .ok_or_else(|| "no `rust-version` in [workspace.package]".to_string())?;

    let out = Command::new("rustc")
        .arg("--version")
        .current_dir(root)
        .output()
        .map_err(|e| format!("cannot run `rustc --version`: {e}"))?;
    if !out.status.success() {
        return Err("`rustc --version` failed".to_string());
    }
    let rustc = String::from_utf8_lossy(&out.stdout).trim().to_string();
    verify(&channel, &rustc, &rust_version)?;
    Ok(format!("ok ({rustc}; rust-version {rust_version})"))
}

/// Compare the pinned channel, the `rustc --version` output, and the MSRV floor.
pub fn verify(channel: &str, rustc_line: &str, rust_version: &str) -> Result<(), String> {
    let actual = rustc_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("cannot parse rustc output {rustc_line:?}"))?;
    if actual != channel {
        return Err(format!(
            "rustc is {actual} but rust-toolchain.toml pins {channel}"
        ));
    }
    if parse_version(rust_version)? > parse_version(channel)? {
        return Err(format!(
            "rust-version {rust_version} is above the pinned channel {channel}"
        ));
    }
    Ok(())
}

fn parse_version(text: &str) -> Result<(u64, u64, u64), String> {
    let mut parts = text.split('.').map(|p| p.parse::<u64>());
    let mut next = |required: bool| -> Result<u64, String> {
        match parts.next() {
            Some(Ok(n)) => Ok(n),
            Some(Err(_)) => Err(format!("bad version {text:?}")),
            None if required => Err(format!("bad version {text:?}")),
            None => Ok(0),
        }
    };
    let v = (next(true)?, next(true)?, next(false)?);
    if parts.next().is_some() {
        return Err(format!("bad version {text:?}"));
    }
    Ok(v)
}

fn toml_string(text: &str, section: Option<&str>, key: &str) -> Option<String> {
    let mut current: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            current = Some(name.trim().to_string());
            continue;
        }
        if section.is_some() && current.as_deref() != section {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                let v = v.split('#').next().unwrap_or("").trim();
                return v
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                    .map(str::to_string);
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn matching_version_passes() {
        assert!(verify("1.94.1", "rustc 1.94.1 (abc 2026-03-01)", "1.88").is_ok());
        assert!(verify("1.94.1", "rustc 1.94.1 (abc 2026-03-01)", "1.94.1").is_ok());
    }

    #[test]
    fn mismatch_or_higher_msrv_fails() {
        assert!(verify("1.94.1", "rustc 1.95.0 (abc 2026-03-01)", "1.88").is_err());
        assert!(verify("1.94.1", "rustc 1.94.1 (abc 2026-03-01)", "1.95").is_err());
    }
}
