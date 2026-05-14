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

fn analyze_hsts(header_name: &str, v: String) -> CheckResult {
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
