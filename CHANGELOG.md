# Changelog

All notable changes to **Strata** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.1] - 2026-10-14

### Added
- **In-Code Rule Suppression with Mandatory Audit Justification:**
  - Syntax support for `# strata:ignore RULE_ID reason: <explanation>` and `// strata:ignore ...`.
  - Proximity matching scoped directly to the target resource block.
  - Strict audit guarantee: directives without mandatory `reason:` are discarded.
  - Distinct terminal reporting table displaying `[SUPPRESSED]` rules with in-source justification reasons.
  - Standard SARIF v2.1.0 `suppressions` object (`inSource` kind with audit justification) for GitHub Code Scanning integration.
  - JSON reporting includes `total_suppressed` count and structured `suppressed` array.

---

## [0.1.0] - 2026-10-13

### Added
- **Core AST Engine:**
  - Fast, zero-dependency HCL syntax parser for Terraform AWS resources.
  - Line-by-line Dockerfile instruction parser.
  - Multi-document Kubernetes YAML manifest normalizer and parser.
- **Security Rule Catalog (15+ CIS & NIST Rules):**
  - `AWS-CIS-S3-001`: S3 bucket public read/write ACL detection.
  - `AWS-CIS-S3-002`: S3 bucket missing default server-side encryption (AES256/KMS).
  - `AWS-CIS-SG-001`: Security group ingress `0.0.0.0/0` on administrative ports (SSH/RDP).
  - `AWS-CIS-SG-002`: Security group ingress `0.0.0.0/0` on database ports (5432, 3306, 27017).
  - `AWS-CIS-RDS-001`: Publicly accessible RDS database instances.
  - `AWS-CIS-RDS-002`: RDS unencrypted storage volume detection.
  - `AWS-CIS-IAM-001`: IAM wildcard administrative policies (`Action: *`, `Resource: *`).
  - `DOCKER-CIS-4.1`: Container image running as root user.
  - `DOCKER-CIS-4.2`: Unpinned or `:latest` base image tags.
  - `DOCKER-CIS-4.3`: Exposed management ports (SSH 22, Docker daemon 2375).
  - `DOCKER-CIS-4.4`: Dangerous pipe-to-shell commands in build layers (`curl | bash`).
  - `K8S-CIS-5.2`: Privileged container execution detection (`privileged: true`).
  - `K8S-CIS-5.3`: Kubernetes pod sharing host network namespace (`hostNetwork: true`).
  - `STRATA-SEC-001`: Committed AWS IAM Access Key ID detection with automatic masking.
  - `STRATA-SEC-002`: Plaintext private encryption key headers in configuration files.
- **Sandboxed Lua 5.4 Extensibility:**
  - Capability-isolated embedded Lua 5.4 runtime.
  - Hardened sandbox blocking `os`, `io`, `package`, and `require`.
  - CPU line hook quota enforcing a 250,000 instruction limit to prevent DoS.
- **Application Security Controls:**
  - `PathSanitizer` defending against directory traversal (`../../`) and symlink escapes.
  - Sensitive credential auto-masking (`AKIA************LE`) across all log streams.
  - Zero external network telemetry guarantee.
- **Developer Experience & Tooling:**
  - Local-first Dev Console web interface (Axum/Tokio) on `http://127.0.0.1:9090`.
  - Native Windows desktop toast notification alerts on policy violations (`--notify`).
  - Standard **SARIF v2.1.0** export for native GitHub Code Scanning tab integration.
  - Clean ANSI terminal output table with unified diff remediation hints.
  - Deterministic CI/CD exit codes (`1` on violations).
