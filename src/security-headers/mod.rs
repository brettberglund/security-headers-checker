#[path = "bad-headers/mod.rs"]
pub mod bad_headers;
#[path = "deprecated-headers/mod.rs"]
pub mod deprecated_headers;
#[path = "required-headers/mod.rs"]
pub mod required_headers;

use crate::header_checker::{CheckResult, HeaderChecker};
use reqwest::header::HeaderMap;

pub fn run_all(headers: &HeaderMap) -> Vec<CheckResult> {
    let checkers: Vec<Box<dyn HeaderChecker>> = vec![
        Box::new(required_headers::hsts::HstsChecker),
        Box::new(required_headers::csp::CspChecker),
        Box::new(required_headers::x_frame_options::XFrameOptionsChecker),
        Box::new(required_headers::x_content_type::XContentTypeOptionsChecker),
        Box::new(required_headers::refer_policy::ReferrerPolicyChecker),
        Box::new(required_headers::permission_policy::PermissionsPolicyChecker),
        Box::new(required_headers::coop::CoopChecker),
        Box::new(required_headers::coep::CoepChecker),
        Box::new(required_headers::corp::CorpChecker),
        Box::new(required_headers::cache_control::CacheControlChecker),
        Box::new(bad_headers::server::ServerChecker),
        Box::new(bad_headers::x_powered_by::XPoweredByChecker),
        Box::new(bad_headers::x_asp_net_version::XAspNetVersionChecker),
        Box::new(bad_headers::x_asp_net_mvc_version::XAspNetMvcVersionChecker),
        Box::new(deprecated_headers::xxss_protection::XXssProtectionChecker),
        Box::new(deprecated_headers::public_key_pins::PublicKeyPinsChecker),
    ];
    checkers.iter().map(|c| c.check(headers)).collect()
}
