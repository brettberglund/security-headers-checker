use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct CacheControlChecker;
impl HeaderChecker for CacheControlChecker {
    fn name(&self) -> &str {
        "Cache-Control"
    }
    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "cache-control") {
            None => CheckResult {
                header: self.name().to_string(),
                status: CheckStatus::Missing,
                severity: Severity::Medium,
                value: None,
                message: "Cache-Control is missing. Sensitive responses may be cached by proxies or browsers.".to_string(),
                remediation: "Add: Cache-Control: no-store on authenticated or sensitive endpoints.".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control".to_string(),
                ],
                context_note: Some(
                    "Critical on authenticated or sensitive endpoints where caching would expose \
                     private data. Public, unauthenticated pages with no sensitive content can \
                     safely omit or relax this header."
                        .to_string(),
                ),
                notes: Some(CACHE_CONTROL_TRADEOFF_NOTE.to_string()),
            },
            Some(v) => analyze_cache_control(self.name(), v),
        }
    }
}

const CACHE_CONTROL_TRADEOFF_NOTE: &str = "Disables all caching, which is actively harmful on high-traffic pages with no sensitive \
     data. It is appropriate mainly for authenticated or otherwise sensitive endpoints, not public \
     static content.";

fn analyze_cache_control(header_name: &str, v: String) -> CheckResult {
    let lower = v.to_lowercase();
    let directives: Vec<&str> = lower.split(',').map(str::trim).collect();

    let has_no_store = directives.contains(&"no-store");
    let has_public = directives.contains(&"public");

    let max_age: Option<u64> = directives
        .iter()
        .find(|d| d.starts_with("max-age="))
        .and_then(|d| d["max-age=".len()..].trim().parse().ok());

    let mut msgs: Vec<String> = vec![];
    // Rank: 2=Medium, 1=Low, 0=Info
    let mut max_rank: u8 = 0;

    if !has_no_store {
        msgs.push(
            "no-store is absent; responses may be cached by browsers or intermediate proxies, \
             exposing sensitive data on shared or public devices"
                .to_string(),
        );
        max_rank = max_rank.max(2);
    }

    if has_public {
        msgs.push(
            "public directive explicitly permits shared-cache storage; \
             avoid on authenticated or sensitive responses"
                .to_string(),
        );
        max_rank = max_rank.max(1);
    }

    if let Some(age) = max_age
        && age > 0
        && has_no_store
    {
        msgs.push(format!(
            "max-age={age} is set alongside no-store; \
             no-store takes precedence but the max-age value is misleading"
        ));
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
            notes: None,
        };
    }

    let severity = match max_rank {
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
        remediation: "Use: Cache-Control: no-store on authenticated or sensitive endpoints."
            .to_string(),
        references: vec![
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control".to_string(),
            "https://owasp.org/www-project-secure-headers/#cache-control".to_string(),
        ],
        context_note: Some(
            "no-store is critical on authenticated or sensitive endpoints. \
             Public, unauthenticated pages with non-sensitive content may intentionally \
             omit it for performance."
                .to_string(),
        ),
        notes: Some(CACHE_CONTROL_TRADEOFF_NOTE.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_checker::{CheckStatus, Severity};
    use crate::test_utils::headers;

    #[test]
    fn missing_is_medium_with_context_note() {
        let r = CacheControlChecker.check(&headers(&[]));
        assert_eq!(r.status, CheckStatus::Missing);
        assert_eq!(r.severity, Severity::Medium);
        assert!(r.context_note.is_some());
    }

    #[test]
    fn no_store_is_present() {
        let r = CacheControlChecker.check(&headers(&[("cache-control", "no-store")]));
        assert_eq!(r.status, CheckStatus::Present);
        assert_eq!(r.severity, Severity::Info);
    }

    #[test]
    fn no_store_no_cache_is_present() {
        let r = CacheControlChecker.check(&headers(&[("cache-control", "no-store, no-cache")]));
        assert_eq!(r.status, CheckStatus::Present);
    }

    #[test]
    fn max_age_only_is_medium() {
        let r = CacheControlChecker.check(&headers(&[("cache-control", "max-age=3600")]));
        assert_eq!(r.status, CheckStatus::Misconfigured);
        assert_eq!(r.severity, Severity::Medium);
        assert!(r.message.contains("no-store"), "got: {}", r.message);
    }

    #[test]
    fn public_max_age_is_medium() {
        let r = CacheControlChecker.check(&headers(&[("cache-control", "public, max-age=3600")]));
        assert_eq!(r.status, CheckStatus::Misconfigured);
        assert_eq!(r.severity, Severity::Medium);
    }

    #[test]
    fn no_store_with_max_age_is_low() {
        let r = CacheControlChecker.check(&headers(&[("cache-control", "no-store, max-age=3600")]));
        assert_eq!(r.status, CheckStatus::Misconfigured);
        assert_eq!(r.severity, Severity::Low);
        assert!(r.message.contains("misleading"), "got: {}", r.message);
    }

    #[test]
    fn public_directive_alone_is_medium() {
        let r = CacheControlChecker.check(&headers(&[("cache-control", "public")]));
        assert_eq!(r.severity, Severity::Medium);
        assert!(r.message.contains("no-store"), "got: {}", r.message);
    }
}
