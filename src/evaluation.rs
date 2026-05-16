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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_checker::{CheckResult, CheckStatus, Severity};

    fn missing(severity: Severity) -> CheckResult {
        CheckResult {
            header: "X".to_string(),
            status: CheckStatus::Missing,
            severity,
            value: None,
            message: String::new(),
            remediation: String::new(),
            references: vec![],
            context_note: None,
        }
    }

    fn missing_with_context(severity: Severity) -> CheckResult {
        CheckResult { context_note: Some("note".to_string()), ..missing(severity) }
    }

    #[test]
    fn grade_boundaries() {
        assert_eq!(compute_grade(100), "A+");
        assert_eq!(compute_grade(95), "A+");
        assert_eq!(compute_grade(94), "A");
        assert_eq!(compute_grade(85), "A");
        assert_eq!(compute_grade(84), "B");
        assert_eq!(compute_grade(70), "B");
        assert_eq!(compute_grade(69), "C");
        assert_eq!(compute_grade(55), "C");
        assert_eq!(compute_grade(54), "D");
        assert_eq!(compute_grade(40), "D");
        assert_eq!(compute_grade(39), "F");
        assert_eq!(compute_grade(0), "F");
    }

    #[test]
    fn report_stem_strips_www() {
        assert_eq!(report_stem("https://www.example.com"), "example");
    }

    #[test]
    fn report_stem_apex_domain() {
        assert_eq!(report_stem("https://example.com"), "example");
    }

    #[test]
    fn report_stem_subdomain() {
        assert_eq!(report_stem("https://api.foo.bar.com"), "api.foo.bar");
    }

    #[test]
    fn report_stem_fallback_on_invalid() {
        assert_eq!(report_stem("not-a-url"), "report");
    }

    #[test]
    fn score_http_url_penalized_20() {
        let score = compute_score("http://example.com", false, &[]);
        assert_eq!(score, 80);
    }

    #[test]
    fn score_no_https_redirect_penalized_10() {
        let score = compute_score("https://example.com", false, &[]);
        assert_eq!(score, 90);
    }

    #[test]
    fn score_https_with_redirect_no_protocol_penalty() {
        let score = compute_score("https://example.com", true, &[]);
        assert_eq!(score, 100);
    }

    #[test]
    fn score_clamps_to_zero() {
        let findings: Vec<CheckResult> = (0..10).map(|_| missing(Severity::Critical)).collect();
        let score = compute_score("https://example.com", true, &findings);
        assert_eq!(score, 0);
    }

    #[test]
    fn context_note_halves_severity_penalty() {
        // Medium = 10 pts, halved = 5, so score = 95
        let findings = vec![missing_with_context(Severity::Medium)];
        let score = compute_score("https://example.com", true, &findings);
        assert_eq!(score, 95);
    }

    #[test]
    fn severity_penalties_are_correct() {
        assert_eq!(severity_penalty(&Severity::Critical), 20);
        assert_eq!(severity_penalty(&Severity::High), 15);
        assert_eq!(severity_penalty(&Severity::Medium), 10);
        assert_eq!(severity_penalty(&Severity::Low), 5);
        assert_eq!(severity_penalty(&Severity::Info), 0);
    }

    #[test]
    fn json_report_filename_format() {
        let p = json_report_filename("https://www.example.com");
        assert_eq!(p, "output/example.json");
    }

    #[test]
    fn json_report_filename_subdomain() {
        let p = json_report_filename("https://api.foo.bar.com");
        assert_eq!(p, "output/api.foo.bar.json");
    }
}
