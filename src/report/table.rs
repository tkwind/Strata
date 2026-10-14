use crate::parser::{Finding, Severity};
use colored::*;

pub struct TerminalReporter;

impl TerminalReporter {
    pub fn render(findings: &[Finding], total_files_scanned: usize, duration_ms: u128) {
        println!();
        println!(
            "{}",
            "STRATA // Infrastructure-as-Code & Cloud Security Audit"
                .bold()
                .white()
        );
        println!(
            "{}",
            "=========================================================================================="
                .dimmed()
        );

        if findings.is_empty() {
            println!(
                "  {} No policy violations detected across {} scanned files. ({} ms)",
                "[PASSED]".green().bold(),
                total_files_scanned,
                duration_ms
            );
            println!(
                "{}",
                "=========================================================================================="
                    .dimmed()
            );
            return;
        }

        // Summary counts
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut med_count = 0;
        let mut low_count = 0;

        for f in findings {
            match f.severity {
                Severity::Critical => critical_count += 1,
                Severity::High => high_count += 1,
                Severity::Medium => med_count += 1,
                Severity::Low => low_count += 1,
            }
        }

        for (idx, f) in findings.iter().enumerate() {
            let sev_tag = match f.severity {
                Severity::Critical => "[CRITICAL]".red().bold(),
                Severity::High => "[HIGH]    ".bright_red().bold(),
                Severity::Medium => "[MEDIUM]  ".yellow().bold(),
                Severity::Low => "[LOW]     ".cyan(),
            };

            println!(
                "#{:<2} {} {} :: {}",
                idx + 1,
                sev_tag,
                f.rule_id.bold().white(),
                f.title.bold()
            );
            println!(
                "     {} {}:{}:{}",
                "Location:".dimmed(),
                f.location.file_path.underline(),
                f.location.line_start,
                f.location.line_end
            );
            println!("     {} {}", "Category:".dimmed(), f.category);
            println!("     {} {}", "Standard:".dimmed(), f.compliance_ref.cyan());
            println!("     {} {}", "Detail:  ".dimmed(), f.description);
            println!("     {} {}", "Remedy:  ".dimmed(), f.remediation.green());
            if !f.location.snippet.is_empty() {
                println!("     {}", "--- Code Snippet ---".dimmed());
                for line in f.location.snippet.lines() {
                    println!("       | {}", line.dimmed());
                }
            }
            println!(
                "{}",
                "------------------------------------------------------------------------------------------"
                    .dimmed()
            );
        }

        println!();
        println!(
            "Audit Summary: {} violations found ({} Critical, {} High, {} Medium, {} Low)",
            findings.len().to_string().bold(),
            critical_count.to_string().red().bold(),
            high_count.to_string().bright_red().bold(),
            med_count.to_string().yellow().bold(),
            low_count.to_string().cyan()
        );
        println!(
            "Scanned: {} files in {} ms",
            total_files_scanned.to_string().bold(),
            duration_ms
        );
        println!(
            "{}",
            "=========================================================================================="
                .dimmed()
        );
    }
}
