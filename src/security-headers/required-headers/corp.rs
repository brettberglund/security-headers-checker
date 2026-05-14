use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct CorpChecker;
impl HeaderChecker for CorpChecker {
    fn name(&self) -> &str {
        "Cross-Origin-Resource-Policy"
    }
    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "cross-origin-resource-policy") {
            None => CheckResult {
                header: self.name().to_string(),
                status: CheckStatus::Missing,
                severity: Severity::Low,
                value: None,
                message: "CORP is missing. Resources may be read by cross-origin pages via speculative execution attacks.".to_string(),
                remediation: "Add: Cross-Origin-Resource-Policy: same-origin".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy".to_string(),
                ],
                context_note: Some(
                    "Most impactful on endpoints that serve embeddable resources (images, scripts, \
                     fonts) intended to be kept private. Document responses that do not serve \
                     cross-origin-loaded assets gain little from this header."
                        .to_string(),
                ),
            },
            Some(v) => CheckResult {
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
