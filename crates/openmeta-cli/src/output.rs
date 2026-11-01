use std::io::IsTerminal;
use std::sync::OnceLock;

use openmeta_core::{SignedRecord, Timestamp};
use openmeta_log::{EquivocationEvidence, SignedCheckpoint};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

fn use_color() -> bool {
    static COLOR: OnceLock<bool> = OnceLock::new();
    *COLOR.get_or_init(|| std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none())
}

fn paint(code: &str, text: &str) -> String {
    if use_color() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn heading(title: &str) {
    println!();
    println!("{}", paint("1", &format!("== {title} ==")));
}

pub fn verified(message: impl AsRef<str>) {
    println!("  {} {}", paint("1;32", "[VERIFIED]"), message.as_ref());
}

pub fn detected(message: impl AsRef<str>) {
    println!("  {} {}", paint("1;31", "[DETECTED]"), message.as_ref());
}

pub fn rejected(message: impl AsRef<str>) {
    println!("  {} {}", paint("1;33", "[REJECTED]"), message.as_ref());
}

pub fn info(message: impl AsRef<str>) {
    println!("  {}", message.as_ref());
}

pub fn field(label: &str, value: impl std::fmt::Display) {
    println!("    {:<18} {value}", format!("{label}:"));
}

pub fn format_time(timestamp: Timestamp) -> String {
    i64::try_from(timestamp.unix_seconds())
        .ok()
        .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_else(|| format!("{} (unix seconds)", timestamp.unix_seconds()))
}

pub fn record(index: u64, record: &SignedRecord) {
    let m = &record.metadata;
    println!("  record #{index}: {} (revision {})", m.purl, m.revision);
    field(
        "publisher",
        format!("{} ({})", m.publisher.name, m.publisher.public_key),
    );
    field(
        "source",
        format!("{} @ {}", m.source.repository, m.source.revision),
    );
    field("artifact sha256", m.artifact_digest);
    field("license", &m.license.spdx_expression);
    field("published", format_time(m.published_at));
    for dependency in &m.dependencies {
        let requirement = dependency.requirement.as_deref().unwrap_or("exact");
        field("dependency", format!("{} ({requirement})", dependency.purl));
    }
    for vulnerability in &m.vulnerabilities {
        field(
            "vulnerability",
            format!("{} ({:?})", vulnerability.id, vulnerability.status),
        );
    }
    if let Some(previous) = m.previous_revision {
        field("supersedes", previous);
    }
    field("content hash", record.content_hash());
    field("signature", record.signature);
}

pub fn checkpoint(checkpoint: &SignedCheckpoint) {
    let cp = &checkpoint.checkpoint;
    println!("  checkpoint size {}", cp.size);
    field("log id", cp.log_id);
    field("root", cp.root);
    field("timestamp", format_time(cp.timestamp));
    field("signature", checkpoint.signature);
}

pub fn evidence(evidence: &EquivocationEvidence) {
    let size = evidence.first.checkpoint.size;
    detected(format!(
        "log {} signed two different roots for size {size}",
        evidence.first.checkpoint.log_id.short()
    ));
    field("root A", evidence.first.checkpoint.root);
    field("signature A", evidence.first.signature);
    field("root B", evidence.second.checkpoint.root);
    field("signature B", evidence.second.signature);
}
