use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct PublicKeyPinsChecker;
impl HeaderChecker for PublicKeyPinsChecker {
    fn name(&self) -> &str {
        "Public-Key-Pins"
    }
    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "public-key-pins") {
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
                severity: Severity::Medium,
                value: Some(v),
                message: "HPKP is deprecated and risks making your site inaccessible if pinned keys are lost.".to_string(),
                remediation: "Remove this header. Prefer Certificate Transparency monitoring instead.".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins".to_string(),
                ],
                context_note: None,
            },
        }
    }
}
