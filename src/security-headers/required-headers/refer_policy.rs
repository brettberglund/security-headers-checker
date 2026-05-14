use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct ReferrerPolicyChecker;

impl HeaderChecker for ReferrerPolicyChecker {
    fn name(&self) -> &str {
        "Referrer-Policy"
    }

    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "referrer-policy") {
            None => CheckResult {
                header: self.name().to_string(),
                status: CheckStatus::Missing,
                severity: Severity::Low,
                value: None,
                message: "Referrer-Policy is missing. Browser default may leak URL data in the \
                          Referer header."
                    .to_string(),
                remediation: "Add: Referrer-Policy: strict-origin-when-cross-origin".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
                        .to_string(),
                ],
                context_note: None,
            },
            Some(v) => {
                // When multiple values are listed, browsers use the last recognised one.
                // Check the last token for the effective policy.
                let effective = v
                    .split(',')
                    .map(str::trim)
                    .rfind(|s| !s.is_empty())
                    .unwrap_or(v.trim())
                    .to_lowercase();

                match effective.as_str() {
                    "unsafe-url" => CheckResult {
                        header: self.name().to_string(),
                        status: CheckStatus::Misconfigured,
                        severity: Severity::Medium,
                        value: Some(v),
                        message: "unsafe-url sends the full URL (including path and query string) \
                                  to all origins, including cross-origin requests over HTTP."
                            .to_string(),
                        remediation: "Use: Referrer-Policy: strict-origin-when-cross-origin"
                            .to_string(),
                        references: vec![
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
                                .to_string(),
                        ],
                        context_note: None,
                    },
                    "no-referrer-when-downgrade" => CheckResult {
                        header: self.name().to_string(),
                        status: CheckStatus::Misconfigured,
                        severity: Severity::Low,
                        value: Some(v),
                        message: "no-referrer-when-downgrade is the old browser default and \
                                  sends the full URL (path and query string) to same-protocol \
                                  origins, potentially leaking sensitive URL components."
                            .to_string(),
                        remediation: "Use: Referrer-Policy: strict-origin-when-cross-origin"
                            .to_string(),
                        references: vec![
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
                                .to_string(),
                        ],
                        context_note: None,
                    },
                    _ => CheckResult {
                        header: self.name().to_string(),
                        status: CheckStatus::Present,
                        severity: Severity::Info,
                        value: Some(v),
                        message: String::new(),
                        remediation: String::new(),
                        references: vec![],
                        context_note: None,
                    },
                }
            }
        }
    }
}
