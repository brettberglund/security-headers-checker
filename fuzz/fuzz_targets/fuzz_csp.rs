#![no_main]
use libfuzzer_sys::fuzz_target;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use security_headers_checker::security_headers::required_headers::csp::CspChecker;
use security_headers_checker::HeaderChecker;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let mut map = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(s) {
            map.insert(
                HeaderName::from_static("content-security-policy"),
                v,
            );
        }
        let _ = CspChecker.check(&map);
    }
});
