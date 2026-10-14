use crate::parser::docker::DockerInstruction;
use crate::parser::k8s::K8sManifest;
use crate::parser::terraform::TerraformResource;
use crate::parser::{Finding, Location, Severity};
use crate::security::PrivacyGuard;
use regex::Regex;
use serde_json::Value;

pub struct BuiltinRuleEngine {
    aws_key_regex: Regex,
    private_key_regex: Regex,
}

impl BuiltinRuleEngine {
    pub fn new() -> Self {
        Self {
            aws_key_regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            private_key_regex: Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
                .unwrap(),
        }
    }

    pub fn evaluate_terraform(&self, resources: &[TerraformResource]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for res in resources {
            match res.resource_type.as_str() {
                "aws_s3_bucket" => {
                    // Rule 1: Public Read ACL
                    if let Some(acl) = res.attributes.get("acl").and_then(|v| v.as_str()) {
                        if acl == "public-read" || acl == "public-read-write" {
                            findings.push(Finding {
                                rule_id: "AWS-CIS-S3-001".to_string(),
                                title: "S3 Bucket allows public read/write access".to_string(),
                                severity: Severity::Critical,
                                category: "Storage / Public Exposure".to_string(),
                                location: res.location.clone(),
                                description: format!(
                                    "Bucket '{}' is configured with overly permissive ACL '{}'. This exposes all stored data to unauthenticated internet traffic.",
                                    res.resource_name, acl
                                ),
                                remediation: "Set 'acl = \"private\"' and enforce S3 Public Access Block at the account or bucket level.".to_string(),
                                compliance_ref: "CIS AWS Foundations Benchmark 1.4 § 2.1.1".to_string(),
                            });
                        }
                    }

                    // Rule 2: Missing Server-Side Encryption
                    let has_encryption = res
                        .sub_blocks
                        .iter()
                        .any(|b| b.block_type == "server_side_encryption_configuration")
                        || res
                            .attributes
                            .contains_key("server_side_encryption_configuration");

                    if !has_encryption {
                        findings.push(Finding {
                            rule_id: "AWS-CIS-S3-002".to_string(),
                            title: "S3 Bucket missing default server-side encryption".to_string(),
                            severity: Severity::High,
                            category: "Storage / Encryption at Rest".to_string(),
                            location: res.location.clone(),
                            description: format!(
                                "Bucket '{}' does not have default server-side encryption configured. Data written to this bucket may be stored unencrypted.",
                                res.resource_name
                            ),
                            remediation: "Add 'server_side_encryption_configuration' block with AES256 or AWS KMS encryption.".to_string(),
                            compliance_ref: "CIS AWS Foundations Benchmark 1.4 § 2.1.2".to_string(),
                        });
                    }
                }

                "aws_security_group" => {
                    // Rule 3 & 4: Ingress 0.0.0.0/0 on SSH/RDP and Database ports
                    for block in &res.sub_blocks {
                        if block.block_type == "ingress" {
                            let cidr_public =
                                block.attributes.get("cidr_blocks").map_or(false, |v| {
                                    if let Some(arr) = v.as_array() {
                                        arr.iter().any(|item| item.as_str() == Some("0.0.0.0/0"))
                                    } else {
                                        v.as_str() == Some("0.0.0.0/0")
                                    }
                                });

                            if cidr_public {
                                let from_port = block
                                    .attributes
                                    .get("from_port")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(-1);
                                let to_port = block
                                    .attributes
                                    .get("to_port")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(-1);

                                // SSH (22) or RDP (3389)
                                if (from_port <= 22 && to_port >= 22)
                                    || (from_port <= 3389 && to_port >= 3389)
                                {
                                    findings.push(Finding {
                                        rule_id: "AWS-CIS-SG-001".to_string(),
                                        title: "Security Group allows ingress 0.0.0.0/0 to administrative port (SSH/RDP)".to_string(),
                                        severity: Severity::Critical,
                                        category: "Network / Unrestricted Ingress".to_string(),
                                        location: res.location.clone(),
                                        description: format!(
                                            "Security group '{}' exposes management ports {}-{} directly to the entire internet (0.0.0.0/0). Enables brute-force attacks.",
                                            res.resource_name, from_port, to_port
                                        ),
                                        remediation: "Restrict CIDR blocks to corporate VPN gateway or bastion host subnets.".to_string(),
                                        compliance_ref: "CIS AWS Foundations Benchmark 1.4 § 5.2".to_string(),
                                    });
                                }

                                // Databases (5432, 3306, 27017)
                                if (from_port <= 5432 && to_port >= 5432)
                                    || (from_port <= 3306 && to_port >= 3306)
                                {
                                    findings.push(Finding {
                                        rule_id: "AWS-CIS-SG-002".to_string(),
                                        title: "Security Group allows unrestricted internet access to database port".to_string(),
                                        severity: Severity::High,
                                        category: "Network / Database Exposure".to_string(),
                                        location: res.location.clone(),
                                        description: format!(
                                            "Security group '{}' opens database port range {}-{} to 0.0.0.0/0. Database instances must never be directly exposed to the public internet.",
                                            res.resource_name, from_port, to_port
                                        ),
                                        remediation: "Limit database ingress strictly to application server security group IDs.".to_string(),
                                        compliance_ref: "CIS AWS Foundations Benchmark 1.4 § 5.3".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }

                "aws_db_instance" => {
                    // Rule 5: RDS Publicly Accessible
                    if let Some(public) = res
                        .attributes
                        .get("publicly_accessible")
                        .and_then(|v| v.as_bool())
                    {
                        if public {
                            findings.push(Finding {
                                rule_id: "AWS-CIS-RDS-001".to_string(),
                                title: "RDS Database instance is publicly accessible".to_string(),
                                severity: Severity::Critical,
                                category: "Database / Public Exposure".to_string(),
                                location: res.location.clone(),
                                description: format!(
                                    "Database '{}' has 'publicly_accessible = true'. Publicly exposed databases are prime targets for automated ransomware attacks.",
                                    res.resource_name
                                ),
                                remediation: "Set 'publicly_accessible = false' and deploy within private database subnets with NAT/VPC peering.".to_string(),
                                compliance_ref: "CIS AWS Foundations Benchmark 1.4 § 2.3.1".to_string(),
                            });
                        }
                    }

                    // Rule 6: RDS Unencrypted Storage
                    let encrypted = res
                        .attributes
                        .get("storage_encrypted")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if !encrypted {
                        findings.push(Finding {
                            rule_id: "AWS-CIS-RDS-002".to_string(),
                            title: "RDS Database storage volume is unencrypted".to_string(),
                            severity: Severity::High,
                            category: "Database / Encryption at Rest".to_string(),
                            location: res.location.clone(),
                            description: format!(
                                "Database '{}' does not have storage encryption enabled. Physical volume snapshots and backups will remain in plaintext.",
                                res.resource_name
                            ),
                            remediation: "Set 'storage_encrypted = true' and specify an AWS KMS key ID.".to_string(),
                            compliance_ref: "CIS AWS Foundations Benchmark 1.4 § 2.3.2".to_string(),
                        });
                    }
                }

                "aws_iam_policy" | "aws_iam_role_policy" => {
                    // Rule 7: Wildcard Action & Resource in IAM
                    if let Some(policy_doc) = res.attributes.get("policy").and_then(|v| v.as_str())
                    {
                        if policy_doc.contains(r#""*""#)
                            && (policy_doc.contains("Action") || policy_doc.contains("Resource"))
                        {
                            findings.push(Finding {
                                rule_id: "AWS-CIS-IAM-001".to_string(),
                                title: "IAM Policy grants wildcard administrative privileges".to_string(),
                                severity: Severity::High,
                                category: "IAM / Least Privilege".to_string(),
                                location: res.location.clone(),
                                description: format!(
                                    "IAM Policy '{}' contains wildcard permissions ('*') granting excessive privileges across AWS services.",
                                    res.resource_name
                                ),
                                remediation: "Follow the principle of least privilege: replace '*' with explicit service actions (e.g. 's3:GetObject').".to_string(),
                                compliance_ref: "CIS AWS Foundations Benchmark 1.4 § 1.16 / NIST 800-53 AC-6".to_string(),
                            });
                        }
                    }
                }

                _ => {}
            }
        }

        findings
    }

    pub fn evaluate_docker(
        &self,
        file_path: &str,
        instructions: &[DockerInstruction],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let mut user_defined = false;
        let mut last_user = "root".to_string();

        for inst in instructions {
            // Rule 8: Unpinned / Latest Image Tag
            if inst.instruction == "FROM" {
                if inst.arguments.contains(":latest") || !inst.arguments.contains(':') {
                    findings.push(Finding {
                        rule_id: "DOCKER-CIS-4.2".to_string(),
                        title: "Base container image uses ':latest' or unpinned version".to_string(),
                        severity: Severity::Medium,
                        category: "Supply Chain / Immutability".to_string(),
                        location: Location {
                            file_path: file_path.to_string(),
                            line_start: inst.line_number,
                            line_end: inst.line_number,
                            snippet: inst.raw_line.clone(),
                        },
                        description: format!(
                            "Dockerfile instruction '{}' pulls an unversioned or ':latest' image. Builds will not be reproducible and are vulnerable to upstream supply chain poisoning.",
                            inst.raw_line
                        ),
                        remediation: "Pin base image to explicit tag and immutable SHA-256 digest (e.g., 'FROM node:20.11.0-alpine@sha256:...').".to_string(),
                        compliance_ref: "CIS Docker Benchmark v1.3.1 § 4.2".to_string(),
                    });
                }
            }

            // Rule 9: Sensitive Port Exposure
            if inst.instruction == "EXPOSE" {
                if inst.arguments.contains("22") || inst.arguments.contains("2375") {
                    findings.push(Finding {
                        rule_id: "DOCKER-CIS-4.3".to_string(),
                        title: "Dockerfile exposes administrative port (SSH or Docker Daemon)".to_string(),
                        severity: Severity::High,
                        category: "Container / Attack Surface".to_string(),
                        location: Location {
                            file_path: file_path.to_string(),
                            line_start: inst.line_number,
                            line_end: inst.line_number,
                            snippet: inst.raw_line.clone(),
                        },
                        description: format!(
                            "Dockerfile exposes port '{}'. Running SSH or unauthenticated Docker daemon (2375) inside containers is an anti-pattern that expands attack surface.",
                            inst.arguments
                        ),
                        remediation: "Remove SSH/daemon port exposure; use container runtime management tooling (e.g., 'kubectl exec' or 'docker exec').".to_string(),
                        compliance_ref: "CIS Docker Benchmark v1.3.1 § 4.3".to_string(),
                    });
                }
            }

            // Rule 10: Dangerous pipe-to-shell in RUN
            if inst.instruction == "RUN" {
                let lower = inst.arguments.to_lowercase();
                if (lower.contains("curl") || lower.contains("wget"))
                    && (lower.contains("| sh")
                        || lower.contains("| bash")
                        || lower.contains("| sudo"))
                {
                    findings.push(Finding {
                        rule_id: "DOCKER-CIS-4.4".to_string(),
                        title: "Dangerous pipe-to-shell command detected in build layer".to_string(),
                        severity: Severity::Critical,
                        category: "Container / Supply Chain".to_string(),
                        location: Location {
                            file_path: file_path.to_string(),
                            line_start: inst.line_number,
                            line_end: inst.line_number,
                            snippet: inst.raw_line.clone(),
                        },
                        description: format!(
                            "Instruction executes arbitrary unverified remote code via pipe-to-shell: '{}'. Vulnerable to MITM attacks and compromised CDNs.",
                            inst.raw_line
                        ),
                        remediation: "Download script, verify GPG signature and cryptographic SHA256 checksum before execution.".to_string(),
                        compliance_ref: "NIST SP 800-190 § 3.1".to_string(),
                    });
                }
            }

            // Track USER instruction
            if inst.instruction == "USER" {
                user_defined = true;
                last_user = inst.arguments.clone();
            }
        }

        // Rule 11: Container runs as Root
        if !user_defined || last_user == "root" || last_user == "0" {
            let last_line = instructions.last().map(|i| i.line_number).unwrap_or(1);
            findings.push(Finding {
                rule_id: "DOCKER-CIS-4.1".to_string(),
                title: "Container image configured to run as root user".to_string(),
                severity: Severity::High,
                category: "Container / Privilege Management".to_string(),
                location: Location {
                    file_path: file_path.to_string(),
                    line_start: last_line,
                    line_end: last_line,
                    snippet: if user_defined { format!("USER {}", last_user) } else { "Missing USER instruction".to_string() },
                },
                description: "No non-root user is defined in the Dockerfile. If the container process is compromised, the adversary gains root privileges on the container and potential host kernel breakout vectors.".to_string(),
                remediation: "Add an explicit non-root user: 'RUN adduser -D -u 10001 appuser && USER appuser'.".to_string(),
                compliance_ref: "CIS Docker Benchmark v1.3.1 § 4.1 / NIST 800-190 § 3.2".to_string(),
            });
        }

        findings
    }

    pub fn evaluate_k8s(&self, file_path: &str, manifests: &[K8sManifest]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for m in manifests {
            let spec = m.raw_json.get("spec").cloned().unwrap_or(Value::Null);

            // Rule 12: Host Network sharing
            if let Some(host_net) = spec.get("hostNetwork").and_then(|v| v.as_bool()) {
                if host_net {
                    findings.push(Finding {
                        rule_id: "K8S-CIS-5.3".to_string(),
                        title: "Kubernetes pod shares host network namespace".to_string(),
                        severity: Severity::High,
                        category: "Kubernetes / Isolation".to_string(),
                        location: Location {
                            file_path: file_path.to_string(),
                            line_start: m.line_number,
                            line_end: m.line_number,
                            snippet: format!("kind: {}\nhostNetwork: true", m.kind),
                        },
                        description: format!(
                            "Workload '{}' has 'hostNetwork: true'. Pod can monitor unencrypted host network traffic and bypass network policies.",
                            m.name
                        ),
                        remediation: "Remove 'hostNetwork: true' to enforce standard container network isolation.".to_string(),
                        compliance_ref: "CIS Kubernetes Benchmark v1.6.0 § 5.2.4".to_string(),
                    });
                }
            }

            // Rule 13: Privileged container
            let containers = spec.get("containers").or_else(|| {
                spec.get("template")
                    .and_then(|t| t.get("spec"))
                    .and_then(|s| s.get("containers"))
            });

            if let Some(c_list) = containers.and_then(|c| c.as_array()) {
                for c in c_list {
                    let privileged = c
                        .get("securityContext")
                        .and_then(|sc| sc.get("privileged"))
                        .and_then(|p| p.as_bool())
                        .unwrap_or(false);

                    if privileged {
                        let c_name = c.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                        findings.push(Finding {
                            rule_id: "K8S-CIS-5.2".to_string(),
                            title: "Kubernetes container runs in privileged mode".to_string(),
                            severity: Severity::Critical,
                            category: "Kubernetes / Host Breakout".to_string(),
                            location: Location {
                                file_path: file_path.to_string(),
                                line_start: m.line_number,
                                line_end: m.line_number,
                                snippet: format!("container: {}\nprivileged: true", c_name),
                            },
                            description: format!(
                                "Container '{}' in workload '{}' has 'privileged: true'. Disables all container security profiles and enables trivial host root breakout.",
                                c_name, m.name
                            ),
                            remediation: "Set 'privileged: false' and drop all Linux capabilities: 'capabilities: { drop: [\"ALL\"] }'.".to_string(),
                            compliance_ref: "CIS Kubernetes Benchmark v1.6.0 § 5.2.5".to_string(),
                        });
                    }
                }
            }
        }

        findings
    }

    pub fn evaluate_raw_secrets(&self, file_path: &str, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            // Rule 14: AWS Access Key ID
            if let Some(m) = self.aws_key_regex.find(line) {
                let masked = PrivacyGuard::mask_sensitive_token(m.as_str());
                findings.push(Finding {
                    rule_id: "STRATA-SEC-001".to_string(),
                    title: "Hardcoded AWS Access Key ID detected in configuration".to_string(),
                    severity: Severity::Critical,
                    category: "Secrets / Leaked Credential".to_string(),
                    location: Location {
                        file_path: file_path.to_string(),
                        line_start: idx + 1,
                        line_end: idx + 1,
                        snippet: format!("Key pattern: {}", masked),
                    },
                    description: format!(
                        "Hardcoded AWS credential '{}' found at line {}. Committing credentials to source code leads to automated cloud account compromise.",
                        masked, idx + 1
                    ),
                    remediation: "Immediately rotate this AWS credential. Use IAM Roles (IRSA/Instance Profiles) or AWS Secrets Manager.".to_string(),
                    compliance_ref: "CIS AWS Foundations Benchmark 1.4 § 1.13 / NIST 800-53 IA-5".to_string(),
                });
            }

            // Rule 15: Private Key Header
            if self.private_key_regex.is_match(line) {
                findings.push(Finding {
                    rule_id: "STRATA-SEC-002".to_string(),
                    title: "Hardcoded private encryption key header detected".to_string(),
                    severity: Severity::Critical,
                    category: "Secrets / Private Key".to_string(),
                    location: Location {
                        file_path: file_path.to_string(),
                        line_start: idx + 1,
                        line_end: idx + 1,
                        snippet: line.trim().to_string(),
                    },
                    description: format!(
                        "Plaintext private key header detected at line {}. Committing private keys exposes cryptographic identity and decrypts traffic.",
                        idx + 1
                    ),
                    remediation: "Remove private key file from version control; store keys exclusively in hardware security modules (HSM) or Vault.".to_string(),
                    compliance_ref: "NIST 800-53 SC-12 / IA-5".to_string(),
                });
            }
        }

        findings
    }
}
