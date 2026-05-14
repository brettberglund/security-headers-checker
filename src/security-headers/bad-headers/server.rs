use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct ServerChecker;

impl HeaderChecker for ServerChecker {
    fn name(&self) -> &str {
        "Server"
    }

    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "server") {
            None => CheckResult {
                header: self.name().to_string(),
                status: CheckStatus::Missing,
                severity: Severity::Info,
                value: None,
                message: String::new(),
                remediation: String::new(),
                references: vec![],
                context_note: None,
            },
            Some(v) => {
                let has_version = contains_version(&v);
                let severity = if has_version {
                    Severity::Medium
                } else {
                    Severity::Low
                };
                let message = if has_version {
                    format!(
                        "Server header exposes version information ('{}'), helping attackers \
                         identify vulnerable software versions.",
                        v
                    )
                } else {
                    "Server header reveals software identity to attackers.".to_string()
                };
                CheckResult {
                    header: self.name().to_string(),
                    status: CheckStatus::Present,
                    severity,
                    value: Some(v),
                    message,
                    remediation:
                        "Remove or genericise the Server header in your web server configuration."
                            .to_string(),
                    references: vec![
                        "https://owasp.org/www-project-secure-headers/#server".to_string(),
                    ],
                    context_note: None,
                }
            }
        }
    }
}

fn contains_version(s: &str) -> bool {
    let b = s.as_bytes();
    for i in 0..b.len().saturating_sub(2) {
        if b[i].is_ascii_digit() && b[i + 1] == b'.' && b[i + 2].is_ascii_digit() {
            return true;
        }
    }
    false
}
