use crate::header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity, get_header};
use reqwest::header::HeaderMap;

pub struct PermissionsPolicyChecker;

impl HeaderChecker for PermissionsPolicyChecker {
    fn name(&self) -> &str {
        "Permissions-Policy"
    }

    fn check(&self, headers: &HeaderMap) -> CheckResult {
        match get_header(headers, "permissions-policy") {
            None => CheckResult {
                header: self.name().to_string(),
                status: CheckStatus::Missing,
                severity: Severity::Low,
                value: None,
                message:
                    "Permissions-Policy is missing. Browser features are not explicitly restricted."
                        .to_string(),
                remediation: "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
                    .to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
                        .to_string(),
                ],
                context_note: Some(
                    "Only materially impactful on pages that use or embed third-party content \
                     capable of requesting camera, microphone, geolocation, or similar browser \
                     features. Static or read-only pages have no features to restrict."
                        .to_string(),
                ),
            },
            Some(v) => analyze_permissions_policy(self.name(), v),
        }
    }
}

const SENSITIVE_FEATURES: &[&str] = &[
    "camera",
    "microphone",
    "geolocation",
    "payment",
    "usb",
    "speaker-selection",
    "bluetooth",
    "hid",
    "serial",
    "display-capture",
    "ambient-light-sensor",
];

fn analyze_permissions_policy(header_name: &str, v: String) -> CheckResult {
    let mut medium_msgs: Vec<String> = vec![];

    for directive in v.split(',') {
        let directive = directive.trim();
        let (name, value) = match directive.find('=') {
            Some(eq) => (directive[..eq].trim(), directive[eq + 1..].trim()),
            None => (directive, ""),
        };
        let name_lower = name.to_lowercase();
        if SENSITIVE_FEATURES.contains(&name_lower.as_str()) && value == "*" {
            medium_msgs.push(format!("{name} is set to * (grants access to all origins)"));
        }
    }

    if medium_msgs.is_empty() {
        CheckResult {
            header: header_name.to_string(),
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
            header: header_name.to_string(),
            status: CheckStatus::Misconfigured,
            severity: Severity::Medium,
            value: Some(v),
            message: medium_msgs.join("; "),
            remediation: "Restrict sensitive features to required origins or deny entirely: \
                 e.g. camera=(), microphone=(), geolocation=(self)"
                .to_string(),
            references: vec![
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
                    .to_string(),
            ],
            context_note: Some(
                "Only materially impactful on pages that use or embed third-party content \
                 capable of requesting camera, microphone, geolocation, or similar browser \
                 features."
                    .to_string(),
            ),
        }
    }
}
