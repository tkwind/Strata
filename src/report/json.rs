use crate::parser::{Finding, SuppressedFinding};
use serde_json::{Value, json};

pub struct JsonReporter;

impl JsonReporter {
    pub fn generate(
        findings: &[Finding],
        suppressed: &[SuppressedFinding],
        total_scanned: usize,
        duration_ms: u128,
    ) -> Value {
        json!({
            "scanner": "strata",
            "version": env!("CARGO_PKG_VERSION"),
            "total_files_scanned": total_scanned,
            "scan_duration_ms": duration_ms,
            "total_violations": findings.len(),
            "total_suppressed": suppressed.len(),
            "findings": findings,
            "suppressed": suppressed
        })
    }
}
