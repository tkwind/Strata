use crate::parser::terraform::TerraformResource;
use crate::parser::{Finding, Severity};
use crate::security::SandboxedLuaEngine;
use serde_json::json;
use std::fs;
use std::path::Path;

pub struct LuaPolicyRunner {
    engine: SandboxedLuaEngine,
    scripts: Vec<(String, String)>, // (filename, script_code)
}

impl LuaPolicyRunner {
    pub fn new(rules_dir: Option<&Path>) -> Result<Self, String> {
        let engine = SandboxedLuaEngine::new(250_000)?; // 250,000 instruction limit per rule
        let mut scripts = Vec::new();

        if let Some(dir) = rules_dir {
            if dir.exists() && dir.is_dir() {
                if let Ok(entries) = fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) == Some("lua") {
                            if let Ok(code) = fs::read_to_string(&path) {
                                let filename =
                                    path.file_name().unwrap().to_string_lossy().to_string();
                                scripts.push((filename, code));
                            }
                        }
                    }
                }
            }
        }

        Ok(Self { engine, scripts })
    }

    pub fn loaded_rule_count(&self) -> usize {
        self.scripts.len()
    }

    pub fn evaluate_terraform_with_lua(&self, resources: &[TerraformResource]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (filename, script_code) in &self.scripts {
            for res in resources {
                let resource_json = json!({
                    "resource_type": res.resource_type,
                    "resource_name": res.resource_name,
                    "attributes": res.attributes,
                    "file_path": res.location.file_path,
                    "line_start": res.location.line_start
                });

                match self.engine.evaluate_rule(script_code, &resource_json) {
                    Ok(result) => {
                        if result.violated {
                            findings.push(Finding {
                                rule_id: format!("LUA-{}", filename.trim_end_matches(".lua").to_uppercase()),
                                title: format!("Custom Sandboxed Lua Policy Violation ({})", filename),
                                severity: Severity::Medium,
                                category: "Custom Organization Policy".to_string(),
                                location: res.location.clone(),
                                description: result.message,
                                remediation: "Follow internal security standards defined in the custom Lua policy rule.".to_string(),
                                compliance_ref: format!("Internal Policy File: {}", filename),
                            });
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[!] Warning: Error evaluating Lua policy '{}': {}",
                            filename, e
                        );
                    }
                }
            }
        }

        findings
    }
}
