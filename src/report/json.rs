use crate::parser::Finding;
use serde_json::{Value, json};

pub struct JsonReporter;

impl JsonReporter {
    pub fn generate(findings: &[Finding], total_scanned: usize, duration_ms: u128) -> Value {
        json!({
            "scanner": "strata",
            "version": "0.1.0",
            "total_files_scanned": total_scanned,
            "scan_duration_ms": duration_ms,
            "total_violations": findings.len(),
            "findings": findings
        })
    }
}
