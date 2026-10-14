use notify_rust::Notification;

/// Native desktop notification subsystem for Windows, macOS, and Linux
pub struct DesktopNotifier;

impl DesktopNotifier {
    /// Dispatches a native desktop notification when security violations are detected
    pub fn send_violation_alert(critical: usize, high: usize, total_files: usize) {
        let total = critical + high;
        if total == 0 {
            return;
        }

        let summary = format!("Strata Security Alert: {} Policy Violations", total);
        let body = format!(
            "Identified {} Critical and {} High infrastructure misconfigurations across {} scanned files.",
            critical, high, total_files
        );

        let _ = Notification::new()
            .appname("Strata Cloud Security")
            .summary(&summary)
            .body(&body)
            .show();
    }

    /// Dispatches a notification confirming clean infrastructure
    pub fn send_clean_alert(total_files: usize) {
        let summary = "Strata: Infrastructure Compliant".to_string();
        let body = format!(
            "All {} infrastructure files passed CIS Benchmarks and NIST 800-53 controls.",
            total_files
        );

        let _ = Notification::new()
            .appname("Strata Cloud Security")
            .summary(&summary)
            .body(&body)
            .show();
    }
}
