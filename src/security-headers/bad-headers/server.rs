use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct ServerChecker;

impl HeaderChecker for ServerChecker {
    fn name(&self) -> &str {
        "Server"
    }

    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "server") {
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
            Some(v) => {
                let has_version = contains_version(&v);
                let severity = if has_version {
                    Severity::Medium
                } else {
                    Severity::Low
                };
                let message = if has_version {
                    format!(
                        "Server header exposes version information ('{}'), helping attackers \
                         identify vulnerable software versions.",
                        v
                    )
                } else {
                    "Server header reveals software identity to attackers.".to_string()
                };
                CheckResult {
                    header: self.name().to_string(),
                    status: CheckStatus::Present,
                    severity,
                    value: Some(v),
                    message,
                    remediation:
                        "Remove or genericise the Server header in your web server configuration."
                            .to_string(),
                    references: vec![
                        "https://owasp.org/www-project-secure-headers/#server".to_string(),
                    ],
                    context_note: None,
                    notes: None,
                }
            }
        }
    }
}

pub(crate) fn contains_version(s: &str) -> bool {
    let b = s.as_bytes();
    for i in 0..b.len().saturating_sub(2) {
        if b[i].is_ascii_digit() && b[i + 1] == b'.' && b[i + 2].is_ascii_digit() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_checker::{CheckStatus, Severity};
    use crate::test_utils::headers;

    #[test]
    fn absent_is_info() {
        let r = ServerChecker.check(&headers(&[]));
        assert_eq!(r.status, CheckStatus::Missing);
        assert_eq!(r.severity, Severity::Info);
        assert!(r.message.is_empty());
    }

    #[test]
    fn server_with_version_is_medium() {
        let r = ServerChecker.check(&headers(&[("server", "Apache/2.4.51")]));
        assert_eq!(r.status, CheckStatus::Present);
        assert_eq!(r.severity, Severity::Medium);
        assert!(
            r.message.contains("version information"),
            "got: {}",
            r.message
        );
    }

    #[test]
    fn server_without_version_is_low() {
        let r = ServerChecker.check(&headers(&[("server", "nginx")]));
        assert_eq!(r.status, CheckStatus::Present);
        assert_eq!(r.severity, Severity::Low);
    }

    #[test]
    fn contains_version_detects_semver_pattern() {
        assert!(contains_version("Apache/2.4.51"));
        assert!(contains_version("nginx/1.21.0"));
        assert!(!contains_version("nginx"));
        assert!(!contains_version(""));
        assert!(!contains_version("v2"));
        assert!(contains_version("2.0.1"));
    }

    #[test]
    fn version_at_string_boundaries() {
        assert!(!contains_version("1.")); // too short for d.d
        assert!(contains_version("1.2"));
        assert!(contains_version("Server 1.2 extra"));
    }
}
