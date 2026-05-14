use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct XAspNetMvcVersionChecker;
impl HeaderChecker for XAspNetMvcVersionChecker {
    fn name(&self) -> &str {
        "X-AspNetMvc-Version"
    }
    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "x-aspnetmvc-version") {
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
                message: "X-AspNetMvc-Version leaks the ASP.NET MVC version.".to_string(),
                remediation:
                    "Call MvcHandler.DisableMvcResponseHeader = true in Application_Start."
                        .to_string(),
                references: vec![],
                context_note: None,
            },
        }
    }
}
