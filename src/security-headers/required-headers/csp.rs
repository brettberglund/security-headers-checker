use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct CspChecker;

impl HeaderChecker for CspChecker {
    fn name(&self) -> &str {
        "Content-Security-Policy"
    }

    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "content-security-policy") {
            None => CheckResult {
                header: self.name().to_string(),
                status: CheckStatus::Missing,
                severity: Severity::High,
                value: None,
                message: "CSP is missing. No control over what resources the browser may load."
                    .to_string(),
                remediation:
                    "Add: Content-Security-Policy: default-src 'self'; frame-ancestors 'none'"
                        .to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP".to_string(),
                    "https://owasp.org/www-project-secure-headers/#content-security-policy"
                        .to_string(),
                ],
                context_note: None,
            },
            Some(v) => analyze_csp(self.name(), v),
        }
    }
}

pub(crate) fn analyze_csp(header_name: &str, v: String) -> CheckResult {
    let mut high_msgs: Vec<String> = vec![];
    let mut medium_msgs: Vec<String> = vec![];

    let directives: Vec<&str> = v
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    let has_default_src = directives.iter().any(|d| {
        d.split_whitespace()
            .next()
            .is_some_and(|n| n.eq_ignore_ascii_case("default-src"))
    });
    let has_frame_ancestors = directives.iter().any(|d| {
        d.split_whitespace()
            .next()
            .is_some_and(|n| n.eq_ignore_ascii_case("frame-ancestors"))
    });

    for dir in &directives {
        let mut parts = dir.split_whitespace();
        let name = match parts.next() {
            Some(n) => n,
            None => continue,
        };
        let values: Vec<&str> = parts.collect();

        for val in &values {
            let vl = val.to_lowercase();
            if vl == "'unsafe-inline'" {
                high_msgs.push(format!("'unsafe-inline' in {name}"));
            }
            if vl == "'unsafe-eval'" {
                high_msgs.push(format!("'unsafe-eval' in {name}"));
            }
        }

        if name.eq_ignore_ascii_case("default-src") && values.contains(&"*") {
            medium_msgs.push("default-src * permits resources from any origin".to_string());
        }
    }

    if !has_default_src {
        medium_msgs.push(
            "missing default-src directive; browser fallback is implicitly allow-all".to_string(),
        );
    }
    if !has_frame_ancestors {
        medium_msgs.push(
            "missing frame-ancestors directive; clickjacking protection relies solely on \
             X-Frame-Options"
                .to_string(),
        );
    }

    if high_msgs.is_empty() && medium_msgs.is_empty() {
        return CheckResult {
            header: header_name.to_string(),
            status: CheckStatus::Present,
            severity: Severity::Info,
            value: Some(v),
            message: String::new(),
            remediation: String::new(),
            references: vec![],
            context_note: None,
        };
    }

    let (severity, mut all_msgs) = if !high_msgs.is_empty() {
        (Severity::High, high_msgs)
    } else {
        (Severity::Medium, vec![])
    };
    all_msgs.extend(medium_msgs);

    CheckResult {
        header: header_name.to_string(),
        status: CheckStatus::Misconfigured,
        severity,
        value: Some(v),
        message: all_msgs.join("; "),
        remediation: "Remove 'unsafe-inline'/'unsafe-eval'; set a restrictive default-src; \
                      add frame-ancestors 'none' or 'self'."
            .to_string(),
        references: vec![
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP".to_string(),
            "https://owasp.org/www-project-secure-headers/#content-security-policy".to_string(),
        ],
        context_note: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_checker::{CheckStatus, Severity};
    use crate::test_utils::headers;

    #[test]
    fn missing_is_high() {
        let r = CspChecker.check(&headers(&[]));
        assert_eq!(r.status, CheckStatus::Missing);
        assert_eq!(r.severity, Severity::High);
    }

    #[test]
    fn perfect_csp_is_present() {
        let r = CspChecker.check(&headers(&[(
            "content-security-policy",
            "default-src 'self'; frame-ancestors 'none'",
        )]));
        assert_eq!(r.status, CheckStatus::Present);
        assert_eq!(r.severity, Severity::Info);
        assert!(r.message.is_empty());
    }

    #[test]
    fn unsafe_inline_is_high() {
        let r = CspChecker.check(&headers(&[(
            "content-security-policy",
            "default-src 'self'; script-src 'unsafe-inline'; frame-ancestors 'none'",
        )]));
        assert_eq!(r.status, CheckStatus::Misconfigured);
        assert_eq!(r.severity, Severity::High);
        assert!(r.message.contains("'unsafe-inline'"), "got: {}", r.message);
    }

    #[test]
    fn unsafe_eval_is_high() {
        let r = CspChecker.check(&headers(&[(
            "content-security-policy",
            "default-src 'self'; script-src 'unsafe-eval'; frame-ancestors 'none'",
        )]));
        assert_eq!(r.severity, Severity::High);
        assert!(r.message.contains("'unsafe-eval'"), "got: {}", r.message);
    }

    #[test]
    fn missing_frame_ancestors_is_medium() {
        let r =
            CspChecker.check(&headers(&[("content-security-policy", "default-src 'self'")]));
        assert_eq!(r.status, CheckStatus::Misconfigured);
        assert_eq!(r.severity, Severity::Medium);
        assert!(r.message.contains("frame-ancestors"), "got: {}", r.message);
    }

    #[test]
    fn missing_default_src_is_medium() {
        let r = CspChecker.check(&headers(&[(
            "content-security-policy",
            "script-src 'self'; frame-ancestors 'none'",
        )]));
        assert_eq!(r.severity, Severity::Medium);
        assert!(r.message.contains("default-src"), "got: {}", r.message);
    }

    #[test]
    fn wildcard_default_src_is_medium() {
        let r = CspChecker.check(&headers(&[(
            "content-security-policy",
            "default-src *; frame-ancestors 'none'",
        )]));
        assert_eq!(r.severity, Severity::Medium);
        assert!(r.message.contains("default-src *"), "got: {}", r.message);
    }

    #[test]
    fn unsafe_inline_outranks_missing_frame_ancestors() {
        let r = CspChecker.check(&headers(&[(
            "content-security-policy",
            "default-src 'self'; script-src 'unsafe-inline'",
        )]));
        // Both unsafe-inline (High) and missing frame-ancestors (Medium) present — High wins
        assert_eq!(r.severity, Severity::High);
    }

    #[test]
    fn case_insensitive_directive_names() {
        let r = CspChecker.check(&headers(&[(
            "content-security-policy",
            "Default-Src 'self'; Frame-Ancestors 'none'",
        )]));
        assert_eq!(r.status, CheckStatus::Present);
    }

    #[test]
    fn analyze_csp_perfect_returns_present() {
        let r = analyze_csp(
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors 'none'".to_string(),
        );
        assert_eq!(r.status, CheckStatus::Present);
    }
}
