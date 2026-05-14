use std::fs;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::header_checker::{CheckResult, Severity};
use crate::http_request::RedirectHop;

#[derive(Serialize, Deserialize)]
pub struct RedirectEntry {
    pub url: String,
    pub status_code: u16,
}

#[derive(Serialize, Deserialize)]
pub struct EvaluationResult {
    pub url: String,
    pub scanned_at: String,
    pub grade: String,
    pub score: u32,
    pub http_to_https: bool,
    pub redirect_chain: Vec<RedirectEntry>,
    pub results: Vec<CheckResult>,
}

pub fn evaluate(
    url: &str,
    http_to_https: bool,
    redirect_chain: Vec<RedirectHop>,
    findings: Vec<CheckResult>,
) -> EvaluationResult {
    let score = compute_score(url, http_to_https, &findings);
    let grade = compute_grade(score).to_string();
    let scanned_at = Utc::now().to_rfc3339();
    let redirect_chain = redirect_chain
        .into_iter()
        .map(|h| RedirectEntry {
            url: h.url,
            status_code: h.status_code,
        })
        .collect();

    EvaluationResult {
        url: url.to_string(),
        scanned_at,
        grade,
        score,
        http_to_https,
        redirect_chain,
        results: findings,
    }
}

pub fn write_json_report(result: &EvaluationResult, path: &str) -> Result<(), String> {
    fs::create_dir_all("output").map_err(|e| format!("Failed to create output dir: {e}"))?;
    let json = serde_json::to_string_pretty(result)
        .map_err(|e| format!("Failed to serialize report: {e}"))?;
    fs::write(path, json).map_err(|e| format!("Failed to write '{path}': {e}"))
}

pub fn json_report_filename(url: &str) -> String {
    format!("output/{}.json", report_stem(url))
}

fn report_stem(url: &str) -> String {
    let host = Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| "report".to_string());

    let trimmed = host.strip_prefix("www.").unwrap_or(&host);
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() > 1 {
        parts[..parts.len() - 1].join(".")
    } else {
        trimmed.to_string()
    }
}

fn compute_score(url: &str, http_to_https: bool, findings: &[CheckResult]) -> u32 {
    let header_deductions: i32 = findings
        .iter()
        .map(|r| {
            let base = severity_penalty(&r.severity) as i32;
            if r.context_note.is_some() {
                base / 2
            } else {
                base
            }
        })
        .sum();

    // Penalise plain-HTTP endpoints and sites that don't enforce HTTPS.
    // Serving over http:// is Critical (20 pts). Having HTTPS but no redirect
    // from HTTP is Medium (10 pts).
    let protocol_deduction: i32 = if url.starts_with("http://") {
        20
    } else if !http_to_https {
        10
    } else {
        0
    };

    (100 - header_deductions - protocol_deduction).max(0) as u32
}

fn severity_penalty(severity: &Severity) -> u32 {
    match severity {
        Severity::Critical => 20,
        Severity::High => 15,
        Severity::Medium => 10,
        Severity::Low => 5,
        Severity::Info => 0,
    }
}

fn compute_grade(score: u32) -> &'static str {
    match score {
        95..=100 => "A+",
        85..=94 => "A",
        70..=84 => "B",
        55..=69 => "C",
        40..=54 => "D",
        _ => "F",
    }
}
