use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct XPoweredByChecker;
impl HeaderChecker for XPoweredByChecker {
    fn name(&self) -> &str {
        "X-Powered-By"
    }
    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "x-powered-by") {
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
                status: CheckStatus::Present,
                severity: Severity::Low,
                value: Some(v),
                message: "X-Powered-By leaks the application framework.".to_string(),
                remediation: "Remove X-Powered-By in your framework or server configuration."
                    .to_string(),
                references: vec![
                    "https://owasp.org/www-project-secure-headers/#x-powered-by".to_string(),
                ],
                context_note: None,
            },
        }
    }
}
