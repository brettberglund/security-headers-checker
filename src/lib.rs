use crate::evaluation::{evaluate, json_report_filename, write_json_report};
use crate::http_request::fetch;
use crate::security_headers::run_all;

mod evaluation;
mod header_checker;
mod http_request;
mod normalize;
mod report;
#[path = "security-headers/mod.rs"]
pub mod security_headers;

pub use header_checker::{CheckResult, CheckStatus, HeaderChecker, Severity};
pub use normalize::normalize_url;
pub use report::generate_html_report;

pub fn run(args: &str) -> Result<String, String> {
    let url = normalize_url(args)?;
    let result = fetch(&url)?;
    let findings = run_all(&result.final_headers);
    let eval = evaluate(
        &result.final_url,
        result.http_to_https,
        result.redirect_chain,
        findings,
    );
    let path = json_report_filename(&result.final_url);
    write_json_report(&eval, &path)?;
    println!("Grade: {}  Score: {}/100", eval.grade, eval.score);
    println!("JSON report written to {path}");
    Ok(path)
}

#[cfg(test)]
pub(crate) mod test_utils {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    pub fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for &(name, value) in pairs {
            map.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }
}
