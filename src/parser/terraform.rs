use super::Location;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerraformSubBlock {
    pub block_type: String,
    pub attributes: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerraformResource {
    pub resource_type: String,
    pub resource_name: String,
    pub attributes: HashMap<String, Value>,
    pub sub_blocks: Vec<TerraformSubBlock>,
    pub location: Location,
}

pub struct TerraformParser;

impl TerraformParser {
    pub fn parse_file(file_path: &str, content: &str) -> Vec<TerraformResource> {
        let lines: Vec<&str> = content.lines().collect();
        let mut resources = Vec::new();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i].trim();
            // Match resource "type" "name" {
            if line.starts_with("resource ") && line.ends_with('{') {
                let parts: Vec<&str> = line.split('"').collect();
                if parts.len() >= 4 {
                    let r_type = parts[1].trim().to_string();
                    let r_name = parts[3].trim().to_string();
                    let line_start = i + 1;

                    // Consume the body of this resource
                    let mut brace_depth = 1;
                    let mut body_lines = Vec::new();
                    let mut j = i + 1;

                    while j < lines.len() && brace_depth > 0 {
                        let cur = lines[j];
                        for ch in cur.chars() {
                            if ch == '{' {
                                brace_depth += 1;
                            } else if ch == '}' {
                                brace_depth -= 1;
                            }
                        }
                        if brace_depth > 0 {
                            body_lines.push(cur);
                        }
                        j += 1;
                    }
                    let line_end = j;

                    // Parse attributes and sub-blocks inside this resource
                    let (attributes, sub_blocks) = Self::parse_block_body(&body_lines);

                    let snippet = if !body_lines.is_empty() {
                        format!("resource \"{}\" \"{}\" {{\n  ...\n}}", r_type, r_name)
                    } else {
                        lines[i].to_string()
                    };

                    resources.push(TerraformResource {
                        resource_type: r_type,
                        resource_name: r_name,
                        attributes,
                        sub_blocks,
                        location: Location {
                            file_path: file_path.to_string(),
                            line_start,
                            line_end,
                            snippet,
                        },
                    });

                    i = j;
                    continue;
                }
            }
            i += 1;
        }

        resources
    }

    fn parse_block_body(lines: &[&str]) -> (HashMap<String, Value>, Vec<TerraformSubBlock>) {
        let mut attributes = HashMap::new();
        let mut sub_blocks = Vec::new();

        let mut idx = 0;
        while idx < lines.len() {
            let trimmed = lines[idx].trim();
            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                idx += 1;
                continue;
            }

            // Check for sub-block e.g. "ingress {" or "server_side_encryption_configuration {"
            if trimmed.ends_with('{') && !trimmed.contains('=') {
                let block_type = trimmed.trim_end_matches('{').trim().to_string();
                let mut sub_depth = 1;
                let mut sub_lines = Vec::new();
                let mut k = idx + 1;

                while k < lines.len() && sub_depth > 0 {
                    let cur = lines[k];
                    for ch in cur.chars() {
                        if ch == '{' {
                            sub_depth += 1;
                        } else if ch == '}' {
                            sub_depth -= 1;
                        }
                    }
                    if sub_depth > 0 {
                        sub_lines.push(cur);
                    }
                    k += 1;
                }

                let (sub_attrs, _) = Self::parse_block_body(&sub_lines);
                sub_blocks.push(TerraformSubBlock {
                    block_type,
                    attributes: sub_attrs,
                });

                idx = k;
                continue;
            }

            // Key-value attribute: key = value
            if let Some((key, val_str)) = trimmed.split_once('=') {
                let clean_key = key.trim().to_string();
                let clean_val = val_str.trim().trim_matches('"');

                let parsed_val = if clean_val == "true" {
                    json!(true)
                } else if clean_val == "false" {
                    json!(false)
                } else if let Ok(n) = clean_val.parse::<i64>() {
                    json!(n)
                } else if clean_val.starts_with('[') && clean_val.ends_with(']') {
                    // Simple list parsing e.g. ["0.0.0.0/0"]
                    let inner = &clean_val[1..clean_val.len() - 1];
                    let items: Vec<Value> = inner
                        .split(',')
                        .map(|s| json!(s.trim().trim_matches('"')))
                        .collect();
                    json!(items)
                } else {
                    json!(clean_val)
                };

                attributes.insert(clean_key, parsed_val);
            }

            idx += 1;
        }

        (attributes, sub_blocks)
    }
}
