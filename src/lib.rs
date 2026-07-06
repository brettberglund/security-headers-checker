use crate::evaluation::{evaluate, json_report_filename, write_json_report};
use crate::http_request::{RedirectHop, fetch};
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
    let had_scheme = args.starts_with("https://") || args.starts_with("http://");
    let url = normalize_url(args)?;

    // If no scheme was given, we default to https://. Some sites don't support
    // https:// at all and the request will error out, so fall back to http://
    // before giving up.
    let result = fetch(&url).or_else(|https_err| {
        if had_scheme {
            Err(https_err)
        } else {
            let http_url = normalize_url(&format!("http://{args}"))?;
            fetch(&http_url).map_err(|_| https_err)
        }
    })?;

    let findings = run_all(&result.final_headers);

    // Include the page the redirect chain landed on, not just the hops that
    // preceded it, so the report shows the full path from start to finish.
    let mut redirect_chain = result.redirect_chain;
    if !redirect_chain.is_empty() {
        redirect_chain.push(RedirectHop {
            url: result.final_url.clone(),
            status_code: result.final_status_code,
            headers: result.final_headers.clone(),
        });
    }

    let eval = evaluate(
        &result.final_url,
        result.http_to_https,
        redirect_chain,
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
