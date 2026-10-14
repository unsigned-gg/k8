//! `cargo xtask spec-check`: validate architecture specifications under `specs/`.
//!
//! Enforces:
//! 1. File names match `SPEC-NNNN-kebab-slug.md` or `NNNN-kebab-slug.md` with unique 4-digit numbers.
//! 2. Closed YAML frontmatter (`---`) at line 1 with valid `status` and date (`created` or `date`).
//! 3. Line count caps: > 300 lines emits a warning; > 400 lines is a hard error.
//! 4. Exactly one H1 heading (`# ...`) outside code fences.
//! 5. Relative markdown links inside `specs/*.md` resolve on disk.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::ExitCode;

const WARN_LINES: usize = 300;
const ERROR_LINES: usize = 400;
const VALID_STATUSES: &[&str] = &[
    "Active",
    "Draft",
    "Superseded",
    "planned",
    "in-progress",
    "complete",
    "archived",
];

/// Validation report for `specs/`.
#[derive(Debug, Default)]
pub struct SpecReport {
    /// Hard validation errors.
    pub errors: Vec<String>,
    /// Soft warnings (e.g., > 300 lines).
    pub warnings: Vec<String>,
    /// Informational notice when `specs/` is empty.
    pub notice: Option<String>,
}

/// CLI entry point for `cargo xtask spec-check`.
pub fn run(root: &Path) -> ExitCode {
    let report = check(root);
    if let Some(notice) = &report.notice {
        println!("spec-check: {notice}");
    }
    for w in &report.warnings {
        println!("warning: {w}");
    }
    for e in &report.errors {
        eprintln!("error: {e}");
    }
    if report.errors.is_empty() {
        println!("spec-check: ok ({} warning(s))", report.warnings.len());
        ExitCode::SUCCESS
    } else {
        eprintln!("spec-check: {} error(s)", report.errors.len());
        ExitCode::FAILURE
    }
}

/// Validate `<root>/specs`.
pub fn check(root: &Path) -> SpecReport {
    let mut report = SpecReport::default();
    let dir = root.join("specs");
    let mut names: Vec<String> = fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter(|e| e.path().is_file())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.ends_with(".md"))
                .collect()
        })
        .unwrap_or_default();
    names.sort();

    if names.is_empty() {
        report.notice =
            Some("no specs found in specs/ (directory missing or empty); nothing to check".into());
        return report;
    }

    let mut numbers: BTreeMap<String, String> = BTreeMap::new();
    for name in names.iter().filter(|n| n.as_str() != "README.md") {
        let rel = format!("specs/{name}");
        let Some(num) = spec_number(name) else {
            report.errors.push(format!(
                "{rel}:1: file name must be SPEC-NNNN-kebab-slug.md or NNNN-kebab-slug.md"
            ));
            continue;
        };
        if let Some(prev) = numbers.get(&num) {
            report.errors.push(format!(
                "{rel}:1: spec number {num} is already used by {prev}"
            ));
            continue;
        }
        numbers.insert(num, name.clone());

        match fs::read_to_string(dir.join(name)) {
            Ok(text) => {
                check_spec_file(&rel, &text, &mut report);
                check_links(&rel, &dir, &text, &mut report);
            }
            Err(e) => report
                .errors
                .push(format!("{rel}:1: cannot read file: {e}")),
        }
    }

    report
}

/// Extract the 4-digit spec number from `SPEC-NNNN-slug.md` or `NNNN-slug.md`.
pub fn spec_number(name: &str) -> Option<String> {
    let stem = name.strip_suffix(".md")?;
    let normalized = stem.strip_prefix("SPEC-").unwrap_or(stem);
    let (num, slug) = normalized.split_once('-')?;
    let digits = num.len() == 4 && num.chars().all(|c| c.is_ascii_digit());
    let slug_ok = !slug.is_empty()
        && slug.split('-').all(|seg| {
            !seg.is_empty()
                && seg
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        });
    (digits && slug_ok).then(|| num.to_string())
}

fn check_spec_file(rel: &str, text: &str, report: &mut SpecReport) {
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() > ERROR_LINES {
        report.errors.push(format!(
            "{rel}:{}: {} lines exceeds the {ERROR_LINES}-line hard cap",
            lines.len(),
            lines.len()
        ));
    } else if lines.len() > WARN_LINES {
        report.warnings.push(format!(
            "{rel}:{}: {} lines exceeds the {WARN_LINES}-line warning threshold",
            lines.len(),
            lines.len()
        ));
    }

    if lines.first().map(|l| l.trim_end()) != Some("---") {
        report
            .errors
            .push(format!("{rel}:1: missing YAML frontmatter (`---`)"));
        return;
    }

    let Some(end) = lines
        .iter()
        .skip(1)
        .position(|l| l.trim_end() == "---")
        .map(|p| p + 1)
    else {
        report
            .errors
            .push(format!("{rel}:1: unclosed YAML frontmatter (`---`)"));
        return;
    };

    let mut seen_keys = BTreeSet::new();
    let mut has_status = false;
    let mut has_date = false;

    for (idx, raw) in lines[1..end].iter().enumerate() {
        let no = idx + 2;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }
        let Some((k, v)) = trimmed.split_once(':') else {
            report
                .errors
                .push(format!("{rel}:{no}: malformed frontmatter entry"));
            continue;
        };
        let key = k.trim();
        let val = v.trim().trim_matches('"').trim_matches('\'');
        if !seen_keys.insert(key.to_string()) {
            report
                .errors
                .push(format!("{rel}:{no}: duplicate frontmatter key `{key}`"));
        }
        if key == "status" {
            has_status = true;
            if !VALID_STATUSES.contains(&val) {
                report.errors.push(format!(
                    "{rel}:{no}: invalid status `{val}` (expected one of {})",
                    VALID_STATUSES.join(", ")
                ));
            }
        }
        if key == "created" || key == "date" {
            has_date = true;
            if !valid_date(val) {
                report.errors.push(format!(
                    "{rel}:{no}: `{key}` value `{val}` must be YYYY-MM-DD"
                ));
            }
        }
    }

    if !has_status {
        report.errors.push(format!(
            "{rel}:1: frontmatter missing required `status` key"
        ));
    }
    if !has_date {
        report.errors.push(format!(
            "{rel}:1: frontmatter missing required `date` or `created` key"
        ));
    }

    let mut in_fence = false;
    let mut h1_count = 0usize;
    for (idx, raw) in lines[end + 1..].iter().enumerate() {
        let no = end + 2 + idx;
        let t = raw.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence && raw.starts_with("# ") {
            h1_count += 1;
            if h1_count > 1 {
                report
                    .errors
                    .push(format!("{rel}:{no}: multiple H1 headings found"));
            }
        }
    }

    if h1_count == 0 {
        report
            .errors
            .push(format!("{rel}:{}: missing H1 heading", end + 2));
    }
}

fn valid_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| s[r].chars().all(|c| c.is_ascii_digit());
    if !(digits(0..4) && digits(5..7) && digits(8..10)) {
        return false;
    }
    let month: u32 = s[5..7].parse().unwrap_or(0);
    let day: u32 = s[8..10].parse().unwrap_or(0);
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

fn check_links(rel: &str, dir: &Path, text: &str, report: &mut SpecReport) {
    let mut in_fence = false;
    for (idx, raw) in text.lines().enumerate() {
        let no = idx + 1;
        let t = raw.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let mut rest = raw;
        while let Some(i) = rest.find("](") {
            rest = &rest[i + 2..];
            if let Some(j) = rest.find(')') {
                if let Some(target) = rest[..j].split_whitespace().next() {
                    let skip = ["http://", "https://", "mailto:", "#", "file://"];
                    if !skip.iter().any(|p| target.starts_with(p)) {
                        let path = target.split('#').next().unwrap_or("");
                        if !path.is_empty() && !dir.join(path).exists() {
                            report
                                .errors
                                .push(format!("{rel}:{no}: broken relative link `{target}`"));
                        }
                    }
                }
                rest = &rest[j..];
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn repo_specs_pass_validation() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let report = check(root);
        assert!(report.errors.is_empty(), "spec errors: {:?}", report.errors);
    }

    #[test]
    fn parses_both_spec_naming_conventions() {
        assert_eq!(
            spec_number("SPEC-0001-k8-architecture-and-roadmap.md").as_deref(),
            Some("0001")
        );
        assert_eq!(spec_number("0002-jury-quorum.md").as_deref(), Some("0002"));
        assert_eq!(spec_number("bad-name.md"), None);
    }
}
