use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct CoepChecker;
impl HeaderChecker for CoepChecker {
    fn name(&self) -> &str {
        "Cross-Origin-Embedder-Policy"
    }
    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "cross-origin-embedder-policy") {
            None => CheckResult {
                header: self.name().to_string(),
                status: CheckStatus::Missing,
                severity: Severity::Info,
                value: None,
                message: "COEP is missing. SharedArrayBuffer is unavailable without it.".to_string(),
                remediation: "Add: Cross-Origin-Embedder-Policy: require-corp (pair with COOP: same-origin)".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy".to_string(),
                ],
                context_note: Some(
                    "Only required when the page opts into cross-origin isolation alongside COOP. \
                     Needed to unlock SharedArrayBuffer and precise performance timers. \
                     Has no effect on pages that do not use those APIs."
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
    fn missing_is_info_with_context_note() {
        let r = CoepChecker.check(&headers(&[]));
        assert_eq!(r.status, CheckStatus::Missing);
        assert_eq!(r.severity, Severity::Info);
        assert!(r.context_note.is_some());
    }

    #[test]
    fn require_corp_is_present() {
        let r = CoepChecker.check(&headers(&[(
            "cross-origin-embedder-policy",
            "require-corp",
        )]));
        assert_eq!(r.status, CheckStatus::Present);
        assert_eq!(r.severity, Severity::Info);
    }
}
