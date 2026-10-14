# Contributing to Strata

Thank you for your interest in contributing to **Strata**! Strata is a high-performance, zero-trust cloud infrastructure-as-code (IaC) security scanner and policy engine written in Rust.

We welcome contributions for new CIS/NIST security rules, parser enhancements, documentation, and performance optimizations.

---

## Code of Conduct

All contributors and maintainers are expected to follow basic professional standards:
- Treat all community members with respect and professionalism.
- Prioritize security, performance, and documentation integrity in all pull requests.
- Report any security vulnerabilities privately per [SECURITY.md](SECURITY.md).

---

## Development Setup

### Prerequisites
- **Rust 1.78+** (with `cargo`, `clippy`, and `rustfmt`)
- **Git**

### Building and Testing

1. **Clone the repository:**
   ```bash
   git clone https://github.com/strata-sec/strata.git
   cd strata
   ```

2. **Run tests:**
   ```bash
   cargo test
   ```

3. **Verify formatting and linter checks:**
   ```bash
   cargo fmt -- --check
   cargo clippy -- -D warnings
   ```

4. **Build release binary:**
   ```bash
   cargo build --release
   ```

---

## How to Add a New Built-in Rule

Built-in rules are compiled in Rust for maximum evaluation speed (<4 ms).

1. Open [`src/rules/builtin.rs`](src/rules/builtin.rs).
2. Choose the appropriate evaluation target:
   - `evaluate_terraform` for AWS/GCP/Azure HCL resources.
   - `evaluate_docker` for Dockerfile instructions.
   - `evaluate_k8s` for Kubernetes workload manifests.
   - `evaluate_raw_secrets` for committed credential patterns.
3. Construct a `Finding` struct adhering to official standards:
   - Include a unique `rule_id` (e.g., `AWS-CIS-S3-003`).
   - Assign a verified `Severity` (`Low`, `Medium`, `High`, `Critical`).
   - Specify the exact **CIS Benchmark** or **NIST 800-53** citation in `compliance_ref`.
   - Provide an actionable, copy-pasteable remediation recommendation.
4. Add a test case in [`tests/scanner_tests.rs`](tests/scanner_tests.rs) with a fixture verifying detection and clean behavior.

---

## How to Author Custom Sandboxed Lua Policies

Organizations can create custom guardrails without modifying the Rust codebase:

1. Place scripts in `rules/*.lua`.
2. Every rule must implement a global `evaluate(resource)` function returning `{ violated = bool, message = string }`:
   ```lua
   function evaluate(resource)
       if resource.resource_type == "aws_s3_bucket" then
           if not resource.attributes.tags or not resource.attributes.tags.Owner then
               return {
                   violated = true,
                   message = "S3 bucket '" .. resource.resource_name .. "' is missing required 'Owner' tag."
               }
           end
       end
       return { violated = false }
   end
   ```
3. Test your rule:
   ```bash
   strata scan ./infrastructure --rules-dir ./rules
   ```

### Sandbox Security Constraints
Custom Lua scripts run inside a capability-isolated Lua 5.4 VM:
- **No filesystem access:** `io`, `loadfile`, and `dofile` are stripped.
- **No OS commands:** `os` and `os.execute` are stripped.
- **No external modules:** `package` and `require` are stripped.
- **Execution quota:** Scripts exceeding **250,000 CPU instructions** are aborted to prevent Denial-of-Service.

---

## Pull Request Guidelines

1. **Keep PRs focused:** Submit separate PRs for unrelated bug fixes, features, or rules.
2. **Include tests:** Any new detection rule must include a corresponding test fixture.
3. **No warnings:** Ensure `cargo clippy -- -D warnings` and `cargo fmt` pass before opening your PR.
4. **Sign-off:** By contributing, you agree that your contributions are licensed under the [Apache-2.0 License](LICENSE).
