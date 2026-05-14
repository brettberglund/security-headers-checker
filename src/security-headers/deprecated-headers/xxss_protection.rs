use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct XXssProtectionChecker;
impl HeaderChecker for XXssProtectionChecker {
    fn name(&self) -> &str {
        "X-XSS-Protection"
    }
    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "x-xss-protection") {
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
            Some(v) => CheckResult {
                header: self.name().to_string(),
                status: CheckStatus::Deprecated,
                severity: Severity::Low,
                value: Some(v),
                message: "X-XSS-Protection is deprecated and can introduce vulnerabilities in older browsers.".to_string(),
                remediation: "Remove this header and use Content-Security-Policy instead.".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection".to_string(),
                ],
                context_note: None,
            },
        }
    }
}
