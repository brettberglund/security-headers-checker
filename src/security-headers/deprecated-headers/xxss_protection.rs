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
                notes: None,
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
        let r = XXssProtectionChecker.check(&headers(&[]));
        assert_eq!(r.status, CheckStatus::Missing);
        assert_eq!(r.severity, Severity::Info);
        assert!(r.message.is_empty());
    }

    #[test]
    fn present_is_deprecated_low() {
        let r = XXssProtectionChecker.check(&headers(&[("x-xss-protection", "1; mode=block")]));
        assert_eq!(r.status, CheckStatus::Deprecated);
        assert_eq!(r.severity, Severity::Low);
        assert!(r.message.contains("deprecated"), "got: {}", r.message);
    }

    #[test]
    fn disabled_value_is_also_deprecated() {
        let r = XXssProtectionChecker.check(&headers(&[("x-xss-protection", "0")]));
        assert_eq!(r.status, CheckStatus::Deprecated);
    }
}
