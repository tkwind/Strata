use std::path::{Path, PathBuf};

/// Security subsystem for path traversal and symlink validation.
/// Prevents directory traversal attacks (e.g., `../../etc/passwd` or malicious symlinks)
/// when Strata scans untrusted repositories.
pub struct PathSanitizer {
    allowed_root: PathBuf,
}

impl PathSanitizer {
    pub fn new(root: &Path) -> Result<Self, String> {
        let canonical_root = root.canonicalize().map_err(|e| {
            format!(
                "Failed to canonicalize base path '{}': {}",
                root.display(),
                e
            )
        })?;
        Ok(Self {
            allowed_root: canonical_root,
        })
    }

    /// Validates that a target path resides strictly within the allowed scan root
    /// and does not traverse outside or point to dangerous system directories.
    pub fn validate_path(&self, target: &Path) -> Result<PathBuf, String> {
        let canonical = match target.canonicalize() {
            Ok(p) => p,
            Err(_) => {
                // If file doesn't exist yet, normalize without symlink resolution
                let mut normalized = self.allowed_root.clone();
                for component in target.components() {
                    match component {
                        std::path::Component::Normal(c) => normalized.push(c),
                        std::path::Component::ParentDir => {
                            if !normalized.pop() || !normalized.starts_with(&self.allowed_root) {
                                return Err(format!(
                                    "Path traversal violation: '{}' escapes scan root",
                                    target.display()
                                ));
                            }
                        }
                        _ => {}
                    }
                }
                return Ok(normalized);
            }
        };

        if !canonical.starts_with(&self.allowed_root) {
            return Err(format!(
                "Path traversal detected: '{}' resolves outside scan root '{}'",
                target.display(),
                self.allowed_root.display()
            ));
        }

        // Block attempts to scan Windows system files
        let path_str = canonical.to_string_lossy().to_lowercase();
        if path_str.contains("windows\\system32") || path_str.contains("/etc/shadow") {
            return Err(format!(
                "Security violation: access to sensitive operating system directory blocked for '{}'",
                canonical.display()
            ));
        }

        Ok(canonical)
    }
}
