pub mod docker;
pub mod k8s;
pub mod terraform;

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl Severity {
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "low" => Some(Severity::Low),
            "med" | "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "crit" | "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file_path: String,
    pub line_start: usize,
    pub line_end: usize,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub category: String,
    pub location: Location,
    pub description: String,
    pub remediation: String,
    pub compliance_ref: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedFile {
    pub file_path: String,
    pub sha256_hash: String,
    pub terraform_resources: Vec<terraform::TerraformResource>,
    pub docker_instructions: Vec<docker::DockerInstruction>,
    pub k8s_manifests: Vec<k8s::K8sManifest>,
    pub raw_lines: Vec<String>,
}
