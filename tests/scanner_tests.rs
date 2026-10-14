// Integration and Unit Tests for Strata Policy Engine

use std::path::Path;
use std::process::Command;

#[test]
fn test_cli_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "--help"])
        .output()
        .expect("Failed to execute cargo run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CIS Benchmarks"));
}

#[test]
fn test_cli_rules_catalog() {
    let output = Command::new("cargo")
        .args(["run", "--", "rules"])
        .output()
        .expect("Failed to execute cargo run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AWS-CIS-S3-001"));
    assert!(stdout.contains("DOCKER-CIS-4.1"));
    assert!(stdout.contains("K8S-CIS-5.2"));
}

#[test]
fn test_scan_hardened_infrastructure_passes() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "scan",
            "tests/fixtures/terraform/hardened_infra.tf",
        ])
        .output()
        .expect("Failed to execute cargo run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[PASSED] No policy violations detected"));
}

#[test]
fn test_scan_vulnerable_infrastructure_fails_with_exit_code_1() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "scan",
            "tests/fixtures/terraform/vulnerable_infra.tf",
        ])
        .output()
        .expect("Failed to execute cargo run");

    // Must exit with code 1 due to Critical & High violations
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AWS-CIS-S3-001"));
    assert!(stdout.contains("AWS-CIS-SG-001"));
    assert!(stdout.contains("AWS-CIS-RDS-001"));
}

#[test]
fn test_sarif_export_format() {
    let sarif_path = "tests/test_output.sarif";
    let _ = std::fs::remove_file(sarif_path);

    let _output = Command::new("cargo")
        .args([
            "run",
            "--",
            "scan",
            "tests/fixtures/docker/Dockerfile.vulnerable",
            "--format",
            "sarif",
            "--output",
            sarif_path,
        ])
        .output()
        .expect("Failed to execute cargo run");

    assert!(Path::new(sarif_path).exists());
    let content = std::fs::read_to_string(sarif_path).unwrap();
    assert!(content.contains("sarif-schema-2.1.0.json"));
    assert!(content.contains("DOCKER-CIS-4.4"));

    let _ = std::fs::remove_file(sarif_path);
}

#[test]
fn test_in_code_rule_suppression_passes_and_shows_justification() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "scan",
            "tests/fixtures/terraform/suppressed_infra.tf",
        ])
        .output()
        .expect("Failed to execute cargo run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[SUPPRESSED]"));
    assert!(stdout.contains("AWS-CIS-S3-001"));
    assert!(
        stdout.contains("Public assets bucket intentionally configured for CDN asset delivery")
    );
    assert!(stdout.contains("1 suppressed"));
}

#[test]
fn test_in_code_rule_suppression_json_output() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "scan",
            "tests/fixtures/terraform/suppressed_infra.tf",
            "--format",
            "json",
        ])
        .output()
        .expect("Failed to execute cargo run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"total_suppressed\": 1"));
    assert!(stdout.contains("\"total_violations\": 0"));
    assert!(
        stdout.contains("Public assets bucket intentionally configured for CDN asset delivery")
    );
}
