use crate::parser::Severity;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrataConfig {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub settings: SettingsConfig,
    #[serde(default)]
    pub rules: RulesConfig,
    #[serde(default)]
    pub exclusions: ExclusionsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsConfig {
    #[serde(default = "default_fail_on")]
    pub fail_on_severity: String,
    #[serde(default = "default_min_severity")]
    pub minimum_severity: String,
}

impl Default for SettingsConfig {
    fn default() -> Self {
        Self {
            fail_on_severity: "HIGH".to_string(),
            minimum_severity: "LOW".to_string(),
        }
    }
}

fn default_fail_on() -> String {
    "HIGH".to_string()
}

fn default_min_severity() -> String {
    "LOW".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RulesConfig {
    #[serde(default)]
    pub ignore: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionsConfig {
    #[serde(default = "default_excluded_paths")]
    pub paths: Vec<String>,
}

fn default_excluded_paths() -> Vec<String> {
    vec![
        ".git".to_string(),
        "node_modules".to_string(),
        "target".to_string(),
        ".terraform".to_string(),
    ]
}

impl Default for ExclusionsConfig {
    fn default() -> Self {
        Self {
            paths: default_excluded_paths(),
        }
    }
}

impl Default for StrataConfig {
    fn default() -> Self {
        Self {
            version: 1,
            settings: SettingsConfig::default(),
            rules: RulesConfig::default(),
            exclusions: ExclusionsConfig::default(),
        }
    }
}

impl StrataConfig {
    pub fn load_or_default(path: Option<&Path>) -> Self {
        if let Some(p) = path {
            if p.exists() {
                if let Ok(content) = fs::read_to_string(p) {
                    if let Ok(cfg) = serde_yaml::from_str::<StrataConfig>(&content) {
                        return cfg;
                    }
                }
            }
        }

        // Try current directory .strata.yaml or .strata.yml
        for candidate in &[".strata.yaml", ".strata.yml"] {
            let p = Path::new(candidate);
            if p.exists() {
                if let Ok(content) = fs::read_to_string(p) {
                    if let Ok(cfg) = serde_yaml::from_str::<StrataConfig>(&content) {
                        return cfg;
                    }
                }
            }
        }

        Self::default()
    }

    pub fn is_rule_ignored(&self, rule_id: &str) -> bool {
        self.rules.ignore.iter().any(|r| r == rule_id)
    }

    pub fn get_fail_on_severity(&self) -> Severity {
        Severity::from_str_loose(&self.settings.fail_on_severity).unwrap_or(Severity::High)
    }

    pub fn get_minimum_severity(&self) -> Severity {
        Severity::from_str_loose(&self.settings.minimum_severity).unwrap_or(Severity::Low)
    }
}
