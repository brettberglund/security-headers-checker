use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct XFrameOptionsChecker;

impl HeaderChecker for XFrameOptionsChecker {
    fn name(&self) -> &str {
        "X-Frame-Options"
    }

    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "x-frame-options") {
            None => CheckResult {
                header: self.name().to_string(),
                status: CheckStatus::Missing,
                severity: Severity::Medium,
                value: None,
                message: "X-Frame-Options is missing. Site may be vulnerable to clickjacking."
                    .to_string(),
                remediation: "Add: X-Frame-Options: DENY (or SAMEORIGIN)".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
                        .to_string(),
                    "https://owasp.org/www-project-secure-headers/#x-frame-options".to_string(),
                ],
                context_note: None,
            },
            Some(v) => {
                let upper = v.trim().to_uppercase();
                if upper == "ALLOWALL" {
                    CheckResult {
                        header: self.name().to_string(),
                        status: CheckStatus::Misconfigured,
                        severity: Severity::High,
                        value: Some(v),
                        message: "ALLOWALL explicitly permits framing by any origin, \
                                  negating clickjacking protection."
                            .to_string(),
                        remediation: "Use DENY or SAMEORIGIN, or prefer \
                                      Content-Security-Policy: frame-ancestors 'none'."
                            .to_string(),
                        references: vec![
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
                                .to_string(),
                            "https://owasp.org/www-project-secure-headers/#x-frame-options"
                                .to_string(),
                        ],
                        context_note: None,
                    }
                } else if upper.starts_with("ALLOW-FROM") {
                    CheckResult {
                        header: self.name().to_string(),
                        status: CheckStatus::Misconfigured,
                        severity: Severity::Medium,
                        value: Some(v),
                        message: "ALLOW-FROM is deprecated and ignored by all modern browsers; \
                                  use CSP frame-ancestors instead."
                            .to_string(),
                        remediation: "Replace with: Content-Security-Policy: \
                                      frame-ancestors 'self' https://trusted.example.com"
                            .to_string(),
                        references: vec![
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
                                .to_string(),
                        ],
                        context_note: None,
                    }
                } else if upper == "DENY" || upper == "SAMEORIGIN" {
                    CheckResult {
                        header: self.name().to_string(),
                        status: CheckStatus::Present,
                        severity: Severity::Info,
                        value: Some(v),
                        message: String::new(),
                        remediation: String::new(),
                        references: vec![],
                        context_note: None,
                    }
                } else {
                    CheckResult {
                        header: self.name().to_string(),
                        status: CheckStatus::Misconfigured,
                        severity: Severity::Medium,
                        value: Some(v.clone()),
                        message: format!(
                            "Unrecognised X-Frame-Options value '{}'; valid values are DENY \
                             and SAMEORIGIN.",
                            v
                        ),
                        remediation: "Use: X-Frame-Options: DENY".to_string(),
                        references: vec![
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
                                .to_string(),
                        ],
                        context_note: None,
                    }
                }
            }
        }
    }
}
