use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct XAspNetVersionChecker;
impl HeaderChecker for XAspNetVersionChecker {
    fn name(&self) -> &str {
        "X-AspNet-Version"
    }
    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "x-aspnet-version") {
            None => CheckResult {
                header: self.name().to_string(),
                status: CheckStatus::Missing,
                severity: Severity::Info,
                value: None,
                message: String::new(),
                remediation: String::new(),
                references: vec![],
                context_note: None,
            },
            Some(v) => CheckResult {
                header: self.name().to_string(),
                status: CheckStatus::Present,
                severity: Severity::Low,
                value: Some(v),
                message: "X-AspNet-Version leaks the ASP.NET runtime version.".to_string(),
                remediation: "Set <httpRuntime enableVersionHeader=\"false\" /> in Web.config."
                    .to_string(),
                references: vec![],
                context_note: None,
            },
        }
    }
}
