#![allow(
    clippy::collapsible_if,
    clippy::collapsible_match,
    clippy::unnecessary_sort_by,
    clippy::derivable_impls,
    clippy::unnecessary_map_or,
    clippy::too_many_arguments
)]

mod config;
mod notify;
mod parser;
mod report;
mod rules;
mod security;
mod server;

use clap::{Parser, Subcommand};
use config::StrataConfig;
use notify::DesktopNotifier;
use parser::docker::DockerParser;
use parser::k8s::K8sParser;
use parser::terraform::TerraformParser;
use parser::{Finding, Severity};
use report::{JsonReporter, SarifReporter, TerminalReporter};
use rules::{BuiltinRuleEngine, LuaPolicyRunner};
use security::PathSanitizer;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;
use walkdir::WalkDir;

#[derive(Parser)]
#[command(
    name = "strata",
    version = "0.1.0",
    about = "Zero-trust Infrastructure-as-Code & Cloud Security Policy Engine",
    long_about = "Strata evaluates Terraform, Dockerfiles, and Kubernetes manifests against CIS Benchmarks, NIST 800-53, and sandboxed Lua rules with deterministic CI/CD exit codes and zero telemetry."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan infrastructure configurations for security vulnerabilities
    Scan {
        /// Target directory or file to scan
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output report format: table, json, sarif
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Minimum severity threshold to display: low, medium, high, critical
        #[arg(short, long)]
        severity: Option<String>,

        /// Break build with exit code 1 if violations reach threshold: low, medium, high, critical
        #[arg(long)]
        fail_on: Option<String>,

        /// Path to custom configuration file (.strata.yaml)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Path to directory containing custom sandboxed Lua rules
        #[arg(long)]
        rules_dir: Option<PathBuf>,

        /// Write output report to a file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Trigger native Windows desktop notification on security warnings
        #[arg(long)]
        notify: bool,

        /// Suppress terminal banners
        #[arg(short, long)]
        quiet: bool,
    },

    /// Launch interactive local Log Dev Panel web server
    Dev {
        /// Port to listen on (default: 9090)
        #[arg(short, long, default_value_t = 9090)]
        port: u16,

        /// Target directory to scan and monitor
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Path to directory containing custom sandboxed Lua rules
        #[arg(long)]
        rules_dir: Option<PathBuf>,
    },

    /// List all loaded CIS, NIST, and custom sandboxed Lua rules
    Rules {
        /// Path to directory containing custom sandboxed Lua rules
        #[arg(long)]
        rules_dir: Option<PathBuf>,
    },

    /// Initialize default .strata.yaml configuration and sample custom Lua policy
    Init,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            init_project();
            ExitCode::SUCCESS
        }
        Commands::Rules { rules_dir } => {
            list_rules(rules_dir.as_deref());
            ExitCode::SUCCESS
        }
        Commands::Dev {
            port,
            path,
            rules_dir,
        } => {
            let rt = tokio::runtime::Runtime::new().expect("Failed to initialize async runtime");
            rt.block_on(server::start_dev_server(port, path, rules_dir));
            ExitCode::SUCCESS
        }
        Commands::Scan {
            path,
            format,
            severity,
            fail_on,
            config,
            rules_dir,
            output,
            notify,
            quiet: _,
        } => run_scan(
            path, format, severity, fail_on, config, rules_dir, output, notify,
        ),
    }
}

fn init_project() {
    let default_config = r#"# Strata Security Configuration (.strata.yaml)
version: 1

settings:
  fail_on_severity: "HIGH" # Break build on HIGH or CRITICAL
  minimum_severity: "LOW"

rules:
  ignore:
    # - "DOCKER-CIS-4.2" # Example: uncomment to ignore unpinned base image warnings

exclusions:
  paths:
    - ".git"
    - "node_modules"
    - "target"
    - ".terraform"

custom_rules:
  dir: "./rules"
"#;

    let sample_lua_rule = r#"-- Custom Sandboxed Lua Policy Rule
-- Strata isolates this script with no filesystem or network access
function evaluate(resource)
    if resource.resource_type == "aws_s3_bucket" then
        -- Check if bucket has an 'Environment' tag
        if not resource.attributes.tags or not resource.attributes.tags.Environment then
            return {
                violated = true,
                message = "S3 bucket '" .. resource.resource_name .. "' is missing required 'Environment' tag"
            }
        end
    end
    return { violated = false }
end
"#;

    let _ = fs::write(".strata.yaml", default_config);
    let _ = fs::create_dir_all("rules");
    let _ = fs::write("rules/require_environment_tag.lua", sample_lua_rule);

    println!("[+] Created default configuration in .strata.yaml");
    println!("[+] Created sample sandboxed Lua rule in rules/require_environment_tag.lua");
}

fn list_rules(rules_dir: Option<&Path>) {
    println!("STRATA // Active Security Rule Catalog");
    println!("==========================================================================");
    let builtin_rules = [
        (
            "AWS-CIS-S3-001",
            "CRITICAL",
            "S3 Bucket allows public read/write access",
            "CIS AWS 1.4 § 2.1.1",
        ),
        (
            "AWS-CIS-S3-002",
            "HIGH",
            "S3 Bucket missing default server-side encryption",
            "CIS AWS 1.4 § 2.1.2",
        ),
        (
            "AWS-CIS-SG-001",
            "CRITICAL",
            "Security Group ingress 0.0.0.0/0 on SSH/RDP",
            "CIS AWS 1.4 § 5.2",
        ),
        (
            "AWS-CIS-SG-002",
            "HIGH",
            "Security Group ingress 0.0.0.0/0 on Database ports",
            "CIS AWS 1.4 § 5.3",
        ),
        (
            "AWS-CIS-RDS-001",
            "CRITICAL",
            "RDS Database instance is publicly accessible",
            "CIS AWS 1.4 § 2.3.1",
        ),
        (
            "AWS-CIS-RDS-002",
            "HIGH",
            "RDS Database storage volume is unencrypted",
            "CIS AWS 1.4 § 2.3.2",
        ),
        (
            "AWS-CIS-IAM-001",
            "HIGH",
            "IAM Policy grants wildcard administrative privileges",
            "CIS AWS 1.4 § 1.16 / NIST AC-6",
        ),
        (
            "DOCKER-CIS-4.1",
            "HIGH",
            "Container image configured to run as root user",
            "CIS Docker 1.3.1 § 4.1",
        ),
        (
            "DOCKER-CIS-4.2",
            "MEDIUM",
            "Base container image uses ':latest' or unpinned tag",
            "CIS Docker 1.3.1 § 4.2",
        ),
        (
            "DOCKER-CIS-4.3",
            "HIGH",
            "Dockerfile exposes administrative port (SSH/Docker)",
            "CIS Docker 1.3.1 § 4.3",
        ),
        (
            "DOCKER-CIS-4.4",
            "CRITICAL",
            "Dangerous pipe-to-shell command in build layer",
            "NIST SP 800-190 § 3.1",
        ),
        (
            "K8S-CIS-5.2",
            "CRITICAL",
            "Kubernetes container runs in privileged mode",
            "CIS K8s 1.6 § 5.2.5",
        ),
        (
            "K8S-CIS-5.3",
            "HIGH",
            "Kubernetes pod shares host network namespace",
            "CIS K8s 1.6 § 5.2.4",
        ),
        (
            "STRATA-SEC-001",
            "CRITICAL",
            "Hardcoded AWS Access Key ID in config",
            "CIS AWS 1.4 § 1.13",
        ),
        (
            "STRATA-SEC-002",
            "CRITICAL",
            "Hardcoded private encryption key header",
            "NIST 800-53 IA-5",
        ),
    ];

    for (id, sev, title, std) in builtin_rules {
        println!("{:<18} [{:<8}] {} ({})", id, sev, title, std);
    }

    if let Ok(runner) = LuaPolicyRunner::new(rules_dir) {
        println!(
            "\nLoaded Custom Sandboxed Lua Rules: {}",
            runner.loaded_rule_count()
        );
    }
    println!("==========================================================================");
}

fn run_scan(
    path: PathBuf,
    format: String,
    severity: Option<String>,
    fail_on: Option<String>,
    config_path: Option<PathBuf>,
    rules_dir: Option<PathBuf>,
    output_file: Option<PathBuf>,
    notify: bool,
) -> ExitCode {
    let start_time = Instant::now();

    // 1. Path Traversal & Security Validation
    let sanitizer = match PathSanitizer::new(Path::new(".")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[!] Security Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let target_dir = match sanitizer.validate_path(&path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[!] Security Violation: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // 2. Load Configuration
    let cfg = StrataConfig::load_or_default(config_path.as_deref());

    let min_severity = severity
        .as_deref()
        .and_then(Severity::from_str_loose)
        .unwrap_or_else(|| cfg.get_minimum_severity());

    let fail_on_severity = fail_on
        .as_deref()
        .and_then(Severity::from_str_loose)
        .unwrap_or_else(|| cfg.get_fail_on_severity());

    // 3. Initialize Engines
    let builtin_engine = BuiltinRuleEngine::new();
    let lua_engine = match LuaPolicyRunner::new(rules_dir.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "[!] Warning: Could not initialize sandboxed Lua engine: {}",
                e
            );
            LuaPolicyRunner::new(None).unwrap()
        }
    };

    let mut total_files_scanned = 0;
    let mut all_findings: Vec<Finding> = Vec::new();

    // 4. File Discovery & Parsing
    let walker = WalkDir::new(&target_dir).into_iter().filter_entry(|e| {
        let name = e.file_name().to_string_lossy();
        !cfg.exclusions
            .paths
            .iter()
            .any(|excluded| name == *excluded)
    });

    for entry in walker.flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }

        let raw_str = p.to_string_lossy();
        let file_str = raw_str.trim_start_matches(r"\\?\").replace('\\', "/");
        let content = match fs::read_to_string(p) {
            Ok(c) => c,
            Err(_) => continue, // Skip binary files safely
        };

        total_files_scanned += 1;

        // Check for raw hardcoded secrets across all parsed files
        let secret_findings = builtin_engine.evaluate_raw_secrets(&file_str, &content);
        all_findings.extend(secret_findings);

        // Terraform (.tf) files
        if p.extension().and_then(|e| e.to_str()) == Some("tf") {
            let resources = TerraformParser::parse_file(&file_str, &content);
            let tf_findings = builtin_engine.evaluate_terraform(&resources);
            all_findings.extend(tf_findings);

            let lua_findings = lua_engine.evaluate_terraform_with_lua(&resources);
            all_findings.extend(lua_findings);
        }

        // Dockerfiles
        let filename = p.file_name().and_then(|f| f.to_str()).unwrap_or("");
        if filename == "Dockerfile" || filename.starts_with("Dockerfile.") {
            let instructions = DockerParser::parse_file(&content);
            let docker_findings = builtin_engine.evaluate_docker(&file_str, &instructions);
            all_findings.extend(docker_findings);
        }

        // Kubernetes YAML manifests
        if p.extension().and_then(|e| e.to_str()) == Some("yaml")
            || p.extension().and_then(|e| e.to_str()) == Some("yml")
        {
            let manifests = K8sParser::parse_file(&content);
            if !manifests.is_empty() {
                let k8s_findings = builtin_engine.evaluate_k8s(&file_str, &manifests);
                all_findings.extend(k8s_findings);
            }
        }
    }

    // 5. Filter findings by config ignore list and minimum severity
    let mut filtered_findings: Vec<Finding> = all_findings
        .into_iter()
        .filter(|f| !cfg.is_rule_ignored(&f.rule_id))
        .filter(|f| f.severity >= min_severity)
        .collect();

    // Sort: Critical first, then High, Medium, Low
    filtered_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    let duration_ms = start_time.elapsed().as_millis();

    // 6. Generate Output
    match format.to_lowercase().as_str() {
        "json" => {
            let json_out =
                JsonReporter::generate(&filtered_findings, total_files_scanned, duration_ms);
            let json_str = serde_json::to_string_pretty(&json_out).unwrap();
            if let Some(out_path) = &output_file {
                let _ = fs::write(out_path, &json_str);
                println!("[+] Report written to {}", out_path.display());
            } else {
                println!("{}", json_str);
            }
        }
        "sarif" => {
            let sarif_out = SarifReporter::generate(&filtered_findings);
            let sarif_str = serde_json::to_string_pretty(&sarif_out).unwrap();
            if let Some(out_path) = &output_file {
                let _ = fs::write(out_path, &sarif_str);
                println!("[+] SARIF report written to {}", out_path.display());
            } else {
                println!("{}", sarif_str);
            }
        }
        _ => {
            TerminalReporter::render(&filtered_findings, total_files_scanned, duration_ms);
            if let Some(out_path) = &output_file {
                let sarif_out = SarifReporter::generate(&filtered_findings);
                let _ = fs::write(out_path, serde_json::to_string_pretty(&sarif_out).unwrap());
                println!("[+] SARIF export saved to {}", out_path.display());
            }
        }
    }

    // 7. Desktop Notification Dispatch
    if notify {
        let mut crit = 0;
        let mut high = 0;
        for f in &filtered_findings {
            if f.severity == Severity::Critical {
                crit += 1;
            } else if f.severity == Severity::High {
                high += 1;
            }
        }
        if crit > 0 || high > 0 {
            DesktopNotifier::send_violation_alert(crit, high, total_files_scanned);
        } else {
            DesktopNotifier::send_clean_alert(total_files_scanned);
        }
    }

    // 8. Deterministic CI/CD Exit Code Evaluation
    let should_fail = filtered_findings
        .iter()
        .any(|f| f.severity >= fail_on_severity);

    if should_fail {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
