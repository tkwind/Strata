use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sManifest {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub raw_json: Value,
    pub line_number: usize,
}

pub struct K8sParser;

impl K8sParser {
    pub fn parse_file(content: &str) -> Vec<K8sManifest> {
        let mut manifests = Vec::new();
        // Split by YAML document separator "---"
        for doc in content.split("\n---") {
            let doc_trimmed = doc.trim();
            if doc_trimmed.is_empty() {
                continue;
            }

            if let Ok(yaml_val) = serde_yaml::from_str::<serde_json::Value>(doc_trimmed) {
                if let (Some(kind), Some(api_ver)) = (
                    yaml_val.get("kind").and_then(|k| k.as_str()),
                    yaml_val.get("apiVersion").and_then(|a| a.as_str()),
                ) {
                    let name = yaml_val
                        .get("metadata")
                        .and_then(|m| m.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("unnamed")
                        .to_string();

                    manifests.push(K8sManifest {
                        api_version: api_ver.to_string(),
                        kind: kind.to_string(),
                        name,
                        raw_json: yaml_val,
                        line_number: 1,
                    });
                }
            }
        }

        manifests
    }
}
