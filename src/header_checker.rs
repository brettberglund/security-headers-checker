use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Present,
    Missing,
    Misconfigured,
    Deprecated,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

pub trait HeaderChecker: Send + Sync {
    fn name(&self) -> &str;
    fn check(&self, headers: &HeaderMap) -> CheckResult;
}

#[derive(Serialize, Deserialize)]
pub struct CheckResult {
    pub header: String,
    pub status: CheckStatus,
    pub severity: Severity,
    pub value: Option<String>,
    pub message: String,
    pub remediation: String,
    pub references: Vec<String>,
    /// Set when the header only matters in specific deployment contexts. Scoring
    /// applies a reduced penalty so pages that genuinely don't need it aren't
    /// unfairly penalised.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_note: Option<String>,
    /// Purely informational: why real-world sites commonly skip or weaken this
    /// header (e.g. it would break OAuth popups, ad embeds, or third-party
    /// widgets). Unlike `context_note`, this never affects scoring.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

pub(crate) fn get_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::headers;

    #[test]
    fn blank_value_is_treated_as_absent() {
        assert_eq!(
            get_header(&headers(&[("x-powered-by", "")]), "x-powered-by"),
            None
        );
    }

    #[test]
    fn whitespace_only_value_is_treated_as_absent() {
        assert_eq!(
            get_header(&headers(&[("x-powered-by", "   ")]), "x-powered-by"),
            None
        );
    }

    #[test]
    fn non_blank_value_is_returned() {
        assert_eq!(
            get_header(&headers(&[("x-powered-by", "PHP/8.1")]), "x-powered-by"),
            Some("PHP/8.1".to_string())
        );
    }

    #[test]
    fn absent_header_is_none() {
        assert_eq!(get_header(&headers(&[]), "x-powered-by"), None);
    }
}
