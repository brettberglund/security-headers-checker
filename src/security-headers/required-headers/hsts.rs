use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct HstsChecker;

impl HeaderChecker for HstsChecker {
    fn name(&self) -> &str {
        "Strict-Transport-Security"
    }

    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "strict-transport-security") {
            None => CheckResult {
                header: self.name().to_string(),
                status: CheckStatus::Missing,
                severity: Severity::Critical,
                value: None,
                message: "HSTS is missing. Non-browser clients (curl, mobile apps, APIs) receive \
                          no upgrade protection, and first-time visitors are vulnerable to \
                          downgrade attacks before any HSTS cache is established. The header is \
                          also required for preload-list eligibility."
                    .to_string(),
                remediation:
                    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                        .to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security".to_string(),
                    "https://owasp.org/www-project-secure-headers/#strict-transport-security"
                        .to_string(),
                ],
                context_note: None,
            },
            Some(v) => analyze_hsts(self.name(), v),
        }
    }
}

pub(crate) fn analyze_hsts(header_name: &str, v: String) -> CheckResult {
    let lower = v.to_lowercase();
    let mut msgs: Vec<String> = vec![];
    // Rank: 3=High, 2=Medium, 1=Low, 0=Info
    let mut max_rank: u8 = 0;

    let max_age: Option<u64> = lower
        .split(';')
        .map(str::trim)
        .find(|d| d.starts_with("max-age"))
        .and_then(|d| d.find('=').map(|i| d[i + 1..].trim().to_string()))
        .and_then(|n| n.parse().ok());

    match max_age {
        None => {
            msgs.push("max-age directive is missing".to_string());
            max_rank = max_rank.max(3);
        }
        Some(age) if age < 15_768_000 => {
            msgs.push(format!(
                "max-age={age} is below 15768000 (6 months); too short to provide meaningful protection"
            ));
            max_rank = max_rank.max(3);
        }
        Some(age) if age < 31_536_000 => {
            msgs.push(format!(
                "max-age={age} is below 31536000 (1 year); site is ineligible for the HSTS preload list"
            ));
            max_rank = max_rank.max(2);
        }
        _ => {}
    }

    let has_include_subdomains = lower
        .split(';')
        .map(str::trim)
        .any(|d| d == "includesubdomains");
    if !has_include_subdomains {
        msgs.push("includeSubDomains is absent; subdomains receive no HSTS protection".to_string());
        max_rank = max_rank.max(1);
    }

    let has_preload = lower.split(';').map(str::trim).any(|d| d == "preload");
    if !has_preload {
        msgs.push(
            "preload is absent; add it and register at hstspreload.org to protect first-time \
             visitors via browser preload lists"
                .to_string(),
        );
        max_rank = max_rank.max(1);
    }

    if msgs.is_empty() {
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

    let severity = match max_rank {
        3 => Severity::High,
        2 => Severity::Medium,
        1 => Severity::Low,
        _ => Severity::Info,
    };

    CheckResult {
        header: header_name.to_string(),
        status: CheckStatus::Misconfigured,
        severity,
        value: Some(v),
        message: msgs.join("; "),
        remediation: "Use: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            .to_string(),
        references: vec![
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
                .to_string(),
            "https://owasp.org/www-project-secure-headers/#strict-transport-security".to_string(),
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
    fn missing_is_critical() {
        let r = HstsChecker.check(&headers(&[]));
        assert_eq!(r.status, CheckStatus::Missing);
        assert_eq!(r.severity, Severity::Critical);
        assert!(r.value.is_none());
    }

    #[test]
    fn perfect_header_is_present() {
        let r = HstsChecker.check(&headers(&[(
            "strict-transport-security",
            "max-age=31536000; includeSubDomains; preload",
        )]));
        assert_eq!(r.status, CheckStatus::Present);
        assert_eq!(r.severity, Severity::Info);
        assert!(r.message.is_empty());
        assert!(r.remediation.is_empty());
    }

    #[test]
    fn short_max_age_is_high() {
        let r = HstsChecker.check(&headers(&[("strict-transport-security", "max-age=1000")]));
        assert_eq!(r.status, CheckStatus::Misconfigured);
        assert_eq!(r.severity, Severity::High);
        assert!(r.message.contains("15768000"), "got: {}", r.message);
    }

    #[test]
    fn zero_max_age_is_high() {
        let r = HstsChecker.check(&headers(&[("strict-transport-security", "max-age=0")]));
        assert_eq!(r.severity, Severity::High);
    }

    #[test]
    fn medium_max_age_is_medium() {
        // 20_000_000 is between 6 months (15_768_000) and 1 year (31_536_000)
        let r = HstsChecker.check(&headers(&[(
            "strict-transport-security",
            "max-age=20000000",
        )]));
        assert_eq!(r.status, CheckStatus::Misconfigured);
        assert_eq!(r.severity, Severity::Medium);
        assert!(r.message.contains("31536000"), "got: {}", r.message);
    }

    #[test]
    fn max_age_only_is_low() {
        let r = HstsChecker.check(&headers(&[(
            "strict-transport-security",
            "max-age=31536000",
        )]));
        assert_eq!(r.severity, Severity::Low);
        assert!(
            r.message.contains("includeSubDomains"),
            "got: {}",
            r.message
        );
        assert!(r.message.contains("preload"), "got: {}", r.message);
    }

    #[test]
    fn missing_only_preload_is_low() {
        let r = HstsChecker.check(&headers(&[(
            "strict-transport-security",
            "max-age=31536000; includeSubDomains",
        )]));
        assert_eq!(r.severity, Severity::Low);
        assert!(r.message.contains("preload"), "got: {}", r.message);
    }

    #[test]
    fn case_insensitive_directives() {
        let r = HstsChecker.check(&headers(&[(
            "strict-transport-security",
            "MAX-AGE=31536000; IncludeSubDomains; Preload",
        )]));
        assert_eq!(r.status, CheckStatus::Present);
    }

    #[test]
    fn missing_max_age_directive_is_high() {
        let r = HstsChecker.check(&headers(&[(
            "strict-transport-security",
            "includeSubDomains; preload",
        )]));
        assert_eq!(r.severity, Severity::High);
        assert!(
            r.message.contains("max-age directive is missing"),
            "got: {}",
            r.message
        );
    }

    #[test]
    fn analyze_hsts_perfect_returns_present() {
        let r = analyze_hsts(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload".to_string(),
        );
        assert_eq!(r.status, CheckStatus::Present);
    }
}
