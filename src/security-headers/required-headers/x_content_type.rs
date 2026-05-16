use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct XContentTypeOptionsChecker;

impl HeaderChecker for XContentTypeOptionsChecker {
    fn name(&self) -> &str {
        "X-Content-Type-Options"
    }

    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "x-content-type-options") {
            None => CheckResult {
                header: self.name().to_string(),
                status: CheckStatus::Missing,
                severity: Severity::Medium,
                value: None,
                message: "X-Content-Type-Options is missing. Browser may MIME-sniff responses."
                    .to_string(),
                remediation: "Add: X-Content-Type-Options: nosniff".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
                        .to_string(),
                ],
                context_note: None,
            },
            Some(v) => {
                if v.trim().eq_ignore_ascii_case("nosniff") {
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
                            "X-Content-Type-Options value '{}' is not recognised; only 'nosniff' \
                             is valid.",
                            v
                        ),
                        remediation: "Set: X-Content-Type-Options: nosniff".to_string(),
                        references: vec![
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
                                .to_string(),
                        ],
                        context_note: None,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_checker::{CheckStatus, Severity};
    use crate::test_utils::headers;

    #[test]
    fn missing_is_medium() {
        let r = XContentTypeOptionsChecker.check(&headers(&[]));
        assert_eq!(r.status, CheckStatus::Missing);
        assert_eq!(r.severity, Severity::Medium);
    }

    #[test]
    fn nosniff_is_present() {
        let r =
            XContentTypeOptionsChecker.check(&headers(&[("x-content-type-options", "nosniff")]));
        assert_eq!(r.status, CheckStatus::Present);
        assert_eq!(r.severity, Severity::Info);
    }

    #[test]
    fn nosniff_uppercase_is_present() {
        let r =
            XContentTypeOptionsChecker.check(&headers(&[("x-content-type-options", "NOSNIFF")]));
        assert_eq!(r.status, CheckStatus::Present);
    }

    #[test]
    fn nosniff_with_whitespace_is_present() {
        let r = XContentTypeOptionsChecker
            .check(&headers(&[("x-content-type-options", "  nosniff  ")]));
        assert_eq!(r.status, CheckStatus::Present);
    }

    #[test]
    fn invalid_value_is_medium() {
        let r =
            XContentTypeOptionsChecker.check(&headers(&[("x-content-type-options", "sniff")]));
        assert_eq!(r.status, CheckStatus::Misconfigured);
        assert_eq!(r.severity, Severity::Medium);
        assert!(r.message.contains("sniff"), "got: {}", r.message);
    }
}
