use crate::parser::{Finding, Severity};
use serde_json::{Value, json};

pub struct SarifReporter;

impl SarifReporter {
    pub fn generate(findings: &[Finding]) -> Value {
        let mut rules = Vec::new();
        let mut results = Vec::new();

        for f in findings {
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
            };

            rules.push(json!({
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": f.description },
                "help": {
                    "text": format!("Remediation: {}\nCompliance Reference: {}", f.remediation, f.compliance_ref)
                },
                "properties": {
                    "category": f.category,
                    "compliance": f.compliance_ref,
                    "security-severity": match f.severity {
                        Severity::Critical => "9.0",
                        Severity::High => "7.5",
                        Severity::Medium => "5.0",
                        Severity::Low => "2.5",
                    }
                }
            }));

            results.push(json!({
                "ruleId": f.rule_id,
                "level": level,
                "message": {
                    "text": format!("{}: {}", f.title, f.description)
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.location.file_path
                            },
                            "region": {
                                "startLine": f.location.line_start,
                                "endLine": f.location.line_end
                            }
                        }
                    }
                ]
            }));
        }

        json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "strata",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/strata-sec/strata",
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        })
    }
}
