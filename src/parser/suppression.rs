use crate::parser::Finding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    pub file_path: String,
    pub rule_ids: Vec<String>,
    pub reason: String,
    pub line_number: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressedFinding {
    pub finding: Finding,
    pub reason: String,
    pub suppression_line: usize,
}

pub struct SuppressionParser;

impl SuppressionParser {
    pub fn parse_content(file_path: &str, content: &str) -> Vec<Suppression> {
        let mut suppressions = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            let comment_body = if let Some(stripped) = trimmed.strip_prefix('#') {
                stripped.trim()
            } else if let Some(stripped) = trimmed.strip_prefix("//") {
                stripped.trim()
            } else {
                continue;
            };

            if let Some(directive) = comment_body.strip_prefix("strata:ignore") {
                let directive = directive.trim();
                if let Some((rules_part, reason_part)) = directive.split_once("reason:") {
                    let rule_ids: Vec<String> = rules_part
                        .split(',')
                        .map(|r| r.trim().to_uppercase())
                        .filter(|r| !r.is_empty())
                        .collect();

                    let reason = reason_part.trim().to_string();

                    if !rule_ids.is_empty() && !reason.is_empty() {
                        suppressions.push(Suppression {
                            file_path: file_path.to_string(),
                            rule_ids,
                            reason,
                            line_number: idx + 1,
                        });
                    }
                }
            }
        }

        suppressions
    }

    pub fn filter_findings(
        findings: Vec<Finding>,
        suppressions: &[Suppression],
    ) -> (Vec<Finding>, Vec<SuppressedFinding>) {
        let mut active = Vec::new();
        let mut suppressed = Vec::new();

        for f in findings {
            let mut matched_suppression = None;

            for s in suppressions {
                if s.file_path == f.location.file_path {
                    let rule_match = s.rule_ids.iter().any(|r| r == &f.rule_id || r == "ALL");
                    if rule_match {
                        let start_bound = f.location.line_start.saturating_sub(3);
                        let end_bound = f.location.line_end;
                        if s.line_number >= start_bound && s.line_number <= end_bound {
                            matched_suppression = Some(s);
                            break;
                        }
                    }
                }
            }

            if let Some(s) = matched_suppression {
                suppressed.push(SuppressedFinding {
                    finding: f,
                    reason: s.reason.clone(),
                    suppression_line: s.line_number,
                });
            } else {
                active.push(f);
            }
        }

        (active, suppressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{Location, Severity};

    #[test]
    fn test_parse_single_rule_suppression() {
        let content = r#"
# strata:ignore AWS-CIS-S3-001 reason: Public assets bucket for marketing CDN
resource "aws_s3_bucket" "cdn" {
  bucket = "marketing-cdn"
}
"#;
        let suppressions = SuppressionParser::parse_content("main.tf", content);
        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].rule_ids, vec!["AWS-CIS-S3-001"]);
        assert_eq!(
            suppressions[0].reason,
            "Public assets bucket for marketing CDN"
        );
        assert_eq!(suppressions[0].line_number, 2);
    }

    #[test]
    fn test_parse_multiple_rules_and_slash_comments() {
        let content = r#"
// strata:ignore AWS-CIS-S3-001, AWS-CIS-S3-002 reason: Legacy staging infrastructure
resource "aws_s3_bucket" "staging" {
  bucket = "staging"
}
"#;
        let suppressions = SuppressionParser::parse_content("staging.tf", content);
        assert_eq!(suppressions.len(), 1);
        assert_eq!(
            suppressions[0].rule_ids,
            vec!["AWS-CIS-S3-001", "AWS-CIS-S3-002"]
        );
        assert_eq!(suppressions[0].reason, "Legacy staging infrastructure");
    }

    #[test]
    fn test_ignore_without_reason_is_rejected() {
        let content = r#"
# strata:ignore AWS-CIS-S3-001
resource "aws_s3_bucket" "unjustified" {
  bucket = "unjustified"
}
"#;
        let suppressions = SuppressionParser::parse_content("main.tf", content);
        assert!(suppressions.is_empty());
    }

    #[test]
    fn test_filter_findings_proximity_matching() {
        let finding = Finding {
            rule_id: "AWS-CIS-S3-001".to_string(),
            title: "S3 Public Read".to_string(),
            description: "Bucket is public".to_string(),
            severity: Severity::Critical,
            remediation: "Set private ACL".to_string(),
            compliance_ref: "CIS AWS 1.4 § 2.1.1".to_string(),
            category: "Cloud Security".to_string(),
            location: Location {
                file_path: "infra.tf".to_string(),
                line_start: 5,
                line_end: 10,
                snippet: String::new(),
            },
        };

        let suppression = Suppression {
            file_path: "infra.tf".to_string(),
            rule_ids: vec!["AWS-CIS-S3-001".to_string()],
            reason: "Intentionally public CDN distribution".to_string(),
            line_number: 4,
        };

        let (active, suppressed) =
            SuppressionParser::filter_findings(vec![finding.clone()], &[suppression]);
        assert!(active.is_empty());
        assert_eq!(suppressed.len(), 1);
        assert_eq!(suppressed[0].suppression_line, 4);
        assert_eq!(
            suppressed[0].reason,
            "Intentionally public CDN distribution"
        );
    }

    #[test]
    fn test_filter_findings_does_not_suppress_different_rule() {
        let finding = Finding {
            rule_id: "AWS-CIS-S3-002".to_string(),
            title: "S3 Missing Encryption".to_string(),
            description: "Bucket is unencrypted".to_string(),
            severity: Severity::High,
            remediation: "Enable SSE".to_string(),
            compliance_ref: "CIS AWS 1.4 § 2.1.2".to_string(),
            category: "Cloud Security".to_string(),
            location: Location {
                file_path: "infra.tf".to_string(),
                line_start: 5,
                line_end: 10,
                snippet: String::new(),
            },
        };

        let suppression = Suppression {
            file_path: "infra.tf".to_string(),
            rule_ids: vec!["AWS-CIS-S3-001".to_string()],
            reason: "Different rule justification".to_string(),
            line_number: 4,
        };

        let (active, suppressed) =
            SuppressionParser::filter_findings(vec![finding], &[suppression]);
        assert_eq!(active.len(), 1);
        assert!(suppressed.is_empty());
    }
}
