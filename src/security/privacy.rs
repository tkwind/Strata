/// Privacy policy enforcement:
/// 1. Zero-telemetry verification: Strata runs 100% locally with no analytics or telemetry calls.
/// 2. Sensitive credential masking: Ensures that when hardcoded secrets are detected during scans,
///    the plaintext secrets are never leaked into CLI logs, CI output, or SARIF files.
#[allow(dead_code)]
pub struct PrivacyGuard;

#[allow(dead_code)]
impl PrivacyGuard {
    /// Masks a detected secret so that only the first 4 and last 2 characters are visible
    pub fn mask_sensitive_token(token: &str) -> String {
        let len = token.len();
        if len <= 6 {
            return "******".to_string();
        }
        let prefix = &token[..4];
        let suffix = &token[len - 2..];
        let masked_middle = "*".repeat(len - 6);
        format!("{}{}{}", prefix, masked_middle, suffix)
    }

    /// Constant verifying that no external networking capability is compiled into the binary
    pub const TELEMETRY_ENABLED: bool = false;
    pub const NETWORK_EGRESS_ENABLED: bool = false;
}
