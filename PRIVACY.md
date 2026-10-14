# Privacy Policy & Local-First Commitment

Strata is built with an absolute **Local-First, Zero-Data-Collection** architecture.

---

## 1. Zero Telemetry
* Strata collects **zero telemetry, usage metrics, IP addresses, or crash logs**.
* The binary is compiled without outbound HTTP clients or external telemetry SDKs.
* Scans are performed 100% locally on your machine or within isolated CI/CD runners (e.g., air-gapped enterprise environments).

---

## 2. Infrastructure Code Confidentiality
* Your Terraform files, Dockerfiles, Kubernetes manifests, and internal cloud configurations are **never uploaded, transmitted, or shared**.
* No external API calls are made to third-party services.

---

## 3. Sensitive Data Masking
* If Strata identifies credentials, access keys, or private certificates during inspection, the findings are masked prior to terminal rendering or SARIF file generation.
* Raw unmasked secret strings are never retained in persistent disk caches or exported reports.

---

## 4. Compliance Auditing
Strata is fully compliant with strict enterprise data governance standards:
* **SOC2 Type II:** No third-party data egress.
* **HIPAA:** No transmission of protected healthcare infrastructure.
* **GDPR:** Zero collection of personal identifiable information (PII).
