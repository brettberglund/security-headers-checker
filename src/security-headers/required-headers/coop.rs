use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct CoopChecker;
impl HeaderChecker for CoopChecker {
    fn name(&self) -> &str {
        "Cross-Origin-Opener-Policy"
    }
    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "cross-origin-opener-policy") {
            None => CheckResult {
                header: self.name().to_string(),
                status: CheckStatus::Missing,
                severity: Severity::Low,
                value: None,
                message: "COOP is missing. Browsing context is not isolated from cross-origin documents.".to_string(),
                remediation: "Add: Cross-Origin-Opener-Policy: same-origin".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy".to_string(),
                ],
                context_note: Some(
                    "Only required if the page uses SharedArrayBuffer or high-resolution timers \
                     that depend on cross-origin isolation. General-purpose pages are unaffected \
                     by its absence."
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_checker::{CheckStatus, Severity};
    use crate::test_utils::headers;

    #[test]
    fn missing_is_low_with_context_note() {
        let r = CoopChecker.check(&headers(&[]));
        assert_eq!(r.status, CheckStatus::Missing);
        assert_eq!(r.severity, Severity::Low);
        assert!(r.context_note.is_some());
    }

    #[test]
    fn same_origin_is_present() {
        let r = CoopChecker.check(&headers(&[("cross-origin-opener-policy", "same-origin")]));
        assert_eq!(r.status, CheckStatus::Present);
        assert_eq!(r.severity, Severity::Info);
    }

    #[test]
    fn any_value_is_present() {
        let r = CoopChecker.check(&headers(&[(
            "cross-origin-opener-policy",
            "same-origin-allow-popups",
        )]));
        assert_eq!(r.status, CheckStatus::Present);
    }
}
