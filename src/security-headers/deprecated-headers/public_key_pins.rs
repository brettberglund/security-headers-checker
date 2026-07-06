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
                notes: None,
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
                notes: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_checker::{CheckStatus, Severity};
    use crate::test_utils::headers;

    #[test]
    fn absent_is_info() {
        let r = PublicKeyPinsChecker.check(&headers(&[]));
        assert_eq!(r.status, CheckStatus::Missing);
        assert_eq!(r.severity, Severity::Info);
    }

    #[test]
    fn present_is_deprecated_medium() {
        let r = PublicKeyPinsChecker.check(&headers(&[(
            "public-key-pins",
            "pin-sha256=\"abc\"; max-age=5184000",
        )]));
        assert_eq!(r.status, CheckStatus::Deprecated);
        assert_eq!(r.severity, Severity::Medium);
        assert!(r.message.contains("deprecated"), "got: {}", r.message);
    }
}
