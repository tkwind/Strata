# Security Policy & Architecture

Strata is designed for zero-trust environments where untrusted or third-party infrastructure-as-code (IaC) repositories and custom rule scripts are evaluated. The application implements defense-in-depth security controls at every layer.

---

## 1. Security Architecture & Threat Model

```
┌────────────────────────────────────────────────────────────────────────┐
│                        UNTRUSTED INPUT BOUNDARY                        │
│   [ Untrusted Git Repos ]    [ Custom User Lua Scripts ]               │
└───────────────────┬───────────────────────────┬────────────────────────┘
                    │                           │
                                               
       [ 1. Path Sanitizer ]           [ 2. Sandboxed Lua VM ]
       - Block Path Traversal          - Capability-stripped (No os/io)
       - Validate Symlinks             - No dynamic C library loading
       - Shield OS files               - 250,000 instruction step quota
                    │                           │
                    └─────────────┬─────────────┘
                                  
                    [ 3. Local-Only Evaluation ]
                    - Zero telemetry / No external sockets
                    - Sensitive secret credential masking
                    - Deterministic exit codes for CI/CD
```

---

## 2. Core Security Controls

### A. Sandboxed Lua 5.4 Execution Runtime
Strata supports custom policy authoring via embedded Lua 5.4 (`src/security/sandbox.rs`). To ensure user-defined or community-contributed policy scripts cannot compromise host systems:
* **Capability Stripping:** The standard library is restricted strictly to `TABLE`, `STRING`, and `MATH`.
* **Prohibited Modules:** Modules providing OS execution (`os`), filesystem access (`io`), module importing (`package`, `require`), and internal reflection (`debug`) are blocked and deleted at runtime.
* **Denial of Service (DoS) Defense:** Strata attaches a CPU line hook that terminates script execution if instruction counts exceed **250,000 steps**, preventing infinite loops and ReDoS attacks.

### B. Path Traversal & Symlink Exploit Defenses
When auditing untrusted codebases, adversaries may craft malicious symlinks or relative path escapes (`../../etc/passwd` or `../../Windows/System32`):
* The `PathSanitizer` (`src/security/path_traversal.rs`) canonicalizes target paths against the root scan boundary.
* Traversals attempting to escape the project directory or access sensitive OS system paths are detected and rejected.

### C. Zero-Telemetry & Data Privacy Guarantee
* **Zero Network Sockets:** Strata contains no HTTP networking libraries, tracking SDKs, or cloud analytics dependencies.
* **Sensitive Token Masking:** When hardcoded secrets (AWS access keys, private certificates) are detected during code scanning, the values are cryptographically masked (`AKIA************LE`) before appearing in terminal output or reports.

---

## 3. Reporting a Security Vulnerability

If you identify a security issue in Strata's sandboxing, path validation, or parser engines:
1. **Do not open a public GitHub issue.**
2. Email security vulnerability reports directly to the maintainers at `security@strata-project.org` with reproduction steps and proof-of-concept manifests.
3. Maintainers will acknowledge within 48 hours and coordinate a coordinated disclosure timeline.
