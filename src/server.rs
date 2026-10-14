use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tower_http::cors::CorsLayer;
use walkdir::WalkDir;

use crate::config::StrataConfig;
use crate::notify::DesktopNotifier;
use crate::parser::docker::DockerParser;
use crate::parser::k8s::K8sParser;
use crate::parser::terraform::TerraformParser;
use crate::parser::{Finding, Severity};
use crate::report::SarifReporter;
use crate::rules::{BuiltinRuleEngine, LuaPolicyRunner};
use crate::security::{PathSanitizer, SandboxedLuaEngine};

const DASHBOARD_HTML: &str = include_str!("../dashboard/index.html");

pub struct ServerState {
    pub scan_root: PathBuf,
    pub rules_dir: Option<PathBuf>,
}

#[derive(Deserialize)]
pub struct LuaTestPayload {
    pub script: String,
}

#[derive(Serialize)]
pub struct LuaTestResponse {
    pub success: bool,
    pub violated: bool,
    pub message: String,
    pub error: Option<String>,
}

pub async fn start_dev_server(port: u16, scan_root: PathBuf, rules_dir: Option<PathBuf>) {
    let state = Arc::new(ServerState {
        scan_root,
        rules_dir,
    });

    let app = Router::new()
        .route("/", get(serve_dashboard))
        .route("/dashboard", get(serve_dashboard))
        .route("/api/scan", get(handle_api_scan))
        .route("/api/sarif", get(handle_api_sarif))
        .route("/api/notify", post(handle_api_notify))
        .route("/api/test-lua", post(handle_api_test_lua))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[!] Failed to bind server to {}: {}", addr, e);
            return;
        }
    };

    println!();
    println!("  STRATA LOG DEV PANEL // LIVE COMMAND CENTER");
    println!("  =======================================================");
    println!("  Local UI:      http://127.0.0.1:{}", port);
    println!("  API Endpoint:  http://127.0.0.1:{}/api/scan", port);
    println!("  SARIF Export:  http://127.0.0.1:{}/api/sarif", port);
    println!("  Zero Telemetry • Offline • Sandboxed Lua Enabled");
    println!("  =======================================================");
    println!();

    // Trigger initial notification confirming launch
    DesktopNotifier::send_clean_alert(1);

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("[!] Server error: {}", e);
    }
}

async fn serve_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

fn execute_internal_scan(root: &Path, rules_dir: Option<&Path>) -> (Vec<Finding>, usize, u128) {
    let start_time = Instant::now();
    let sanitizer =
        PathSanitizer::new(Path::new(".")).unwrap_or_else(|_| PathSanitizer::new(root).unwrap());
    let target_dir = sanitizer
        .validate_path(root)
        .unwrap_or_else(|_| root.to_path_buf());

    let cfg = StrataConfig::load_or_default(None);
    let builtin_engine = BuiltinRuleEngine::new();
    let lua_engine =
        LuaPolicyRunner::new(rules_dir).unwrap_or_else(|_| LuaPolicyRunner::new(None).unwrap());

    let mut total_files_scanned = 0;
    let mut all_findings: Vec<Finding> = Vec::new();

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
            Err(_) => continue,
        };

        total_files_scanned += 1;

        let secret_findings = builtin_engine.evaluate_raw_secrets(&file_str, &content);
        all_findings.extend(secret_findings);

        if p.extension().and_then(|e| e.to_str()) == Some("tf") {
            let resources = TerraformParser::parse_file(&file_str, &content);
            all_findings.extend(builtin_engine.evaluate_terraform(&resources));
            all_findings.extend(lua_engine.evaluate_terraform_with_lua(&resources));
        }

        let filename = p.file_name().and_then(|f| f.to_str()).unwrap_or("");
        if filename == "Dockerfile" || filename.starts_with("Dockerfile.") {
            let instructions = DockerParser::parse_file(&content);
            all_findings.extend(builtin_engine.evaluate_docker(&file_str, &instructions));
        }

        if p.extension().and_then(|e| e.to_str()) == Some("yaml")
            || p.extension().and_then(|e| e.to_str()) == Some("yml")
        {
            let manifests = K8sParser::parse_file(&content);
            if !manifests.is_empty() {
                all_findings.extend(builtin_engine.evaluate_k8s(&file_str, &manifests));
            }
        }
    }

    let mut filtered_findings: Vec<Finding> = all_findings
        .into_iter()
        .filter(|f| !cfg.is_rule_ignored(&f.rule_id))
        .collect();

    filtered_findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    let elapsed_ms = start_time.elapsed().as_millis();

    (filtered_findings, total_files_scanned, elapsed_ms)
}

async fn handle_api_scan(State(state): State<Arc<ServerState>>) -> Json<Value> {
    let (findings, files_scanned, elapsed_ms) =
        execute_internal_scan(&state.scan_root, state.rules_dir.as_deref());

    // Calculate critical/high counts
    let mut critical = 0;
    let mut high = 0;
    for f in &findings {
        if f.severity == Severity::Critical {
            critical += 1;
        } else if f.severity == Severity::High {
            high += 1;
        }
    }

    if critical > 0 || high > 0 {
        DesktopNotifier::send_violation_alert(critical, high, files_scanned);
    }

    Json(json!({
        "status": "success",
        "scanner": "strata",
        "total_files_scanned": files_scanned,
        "scan_duration_ms": elapsed_ms,
        "total_violations": findings.len(),
        "findings": findings
    }))
}

async fn handle_api_sarif(State(state): State<Arc<ServerState>>) -> Response {
    let (findings, _, _) = execute_internal_scan(&state.scan_root, state.rules_dir.as_deref());
    let sarif_val = SarifReporter::generate(&findings);
    let body = serde_json::to_string_pretty(&sarif_val).unwrap();

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"strata-results.sarif\"",
            ),
        ],
        body,
    )
        .into_response()
}

async fn handle_api_notify() -> Json<Value> {
    DesktopNotifier::send_violation_alert(3, 2, 5);
    Json(json!({ "status": "dispatched", "message": "Windows desktop notification sent" }))
}

async fn handle_api_test_lua(Json(payload): Json<LuaTestPayload>) -> Json<LuaTestResponse> {
    let sample_resource = json!({
        "resource_type": "aws_s3_bucket",
        "resource_name": "customer_backup_data",
        "attributes": {
            "bucket": "prod-backups",
            "acl": "public-read"
        },
        "file_path": "main.tf",
        "line_start": 1
    });

    let engine = match SandboxedLuaEngine::new(250_000) {
        Ok(e) => e,
        Err(err) => {
            return Json(LuaTestResponse {
                success: false,
                violated: false,
                message: String::new(),
                error: Some(err),
            });
        }
    };

    match engine.evaluate_rule(&payload.script, &sample_resource) {
        Ok(res) => Json(LuaTestResponse {
            success: true,
            violated: res.violated,
            message: res.message,
            error: None,
        }),
        Err(e) => Json(LuaTestResponse {
            success: false,
            violated: false,
            message: String::new(),
            error: Some(e),
        }),
    }
}
