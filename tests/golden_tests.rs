mod common;

use security_headers_checker::security_headers::required_headers::{
    cache_control::CacheControlChecker,
    csp::CspChecker,
    hsts::HstsChecker,
    refer_policy::ReferrerPolicyChecker,
    x_frame_options::XFrameOptionsChecker,
};
use security_headers_checker::security_headers::bad_headers::server::ServerChecker;
use security_headers_checker::security_headers::deprecated_headers::{
    public_key_pins::PublicKeyPinsChecker, xxss_protection::XXssProtectionChecker,
};
use security_headers_checker::HeaderChecker;

// ── HSTS ─────────────────────────────────────────────────────────────────────

#[test]
fn hsts_missing() {
    let r = HstsChecker.check(&common::headers(&[]));
    common::assert_golden(&serde_json::to_value(r).unwrap(), "hsts/missing.json");
}

#[test]
fn hsts_perfect() {
    let r = HstsChecker.check(&common::headers(&[(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains; preload",
    )]));
    common::assert_golden(&serde_json::to_value(r).unwrap(), "hsts/perfect.json");
}

#[test]
fn hsts_short_max_age() {
    let r = HstsChecker.check(&common::headers(&[("strict-transport-security", "max-age=1000")]));
    common::assert_golden(&serde_json::to_value(r).unwrap(), "hsts/short_max_age.json");
}

#[test]
fn hsts_medium_max_age() {
    let r = HstsChecker
        .check(&common::headers(&[("strict-transport-security", "max-age=20000000")]));
    common::assert_golden(&serde_json::to_value(r).unwrap(), "hsts/medium_max_age.json");
}

#[test]
fn hsts_no_subdomains() {
    let r = HstsChecker
        .check(&common::headers(&[("strict-transport-security", "max-age=31536000")]));
    common::assert_golden(&serde_json::to_value(r).unwrap(), "hsts/no_subdomains.json");
}

// ── CSP ──────────────────────────────────────────────────────────────────────

#[test]
fn csp_missing() {
    let r = CspChecker.check(&common::headers(&[]));
    common::assert_golden(&serde_json::to_value(r).unwrap(), "csp/missing.json");
}

#[test]
fn csp_perfect() {
    let r = CspChecker.check(&common::headers(&[(
        "content-security-policy",
        "default-src 'self'; frame-ancestors 'none'",
    )]));
    common::assert_golden(&serde_json::to_value(r).unwrap(), "csp/perfect.json");
}

#[test]
fn csp_unsafe_inline() {
    let r = CspChecker.check(&common::headers(&[(
        "content-security-policy",
        "default-src 'self'; script-src 'unsafe-inline'; frame-ancestors 'none'",
    )]));
    common::assert_golden(&serde_json::to_value(r).unwrap(), "csp/unsafe_inline.json");
}

#[test]
fn csp_no_frame_ancestors() {
    let r = CspChecker.check(&common::headers(&[(
        "content-security-policy",
        "default-src 'self'",
    )]));
    common::assert_golden(&serde_json::to_value(r).unwrap(), "csp/no_frame_ancestors.json");
}

#[test]
fn csp_wildcard_default_src() {
    let r = CspChecker.check(&common::headers(&[(
        "content-security-policy",
        "default-src *; frame-ancestors 'none'",
    )]));
    common::assert_golden(
        &serde_json::to_value(r).unwrap(),
        "csp/wildcard_default_src.json",
    );
}

// ── X-Frame-Options ──────────────────────────────────────────────────────────

#[test]
fn xfo_missing() {
    let r = XFrameOptionsChecker.check(&common::headers(&[]));
    common::assert_golden(&serde_json::to_value(r).unwrap(), "x_frame_options/missing.json");
}

#[test]
fn xfo_deny() {
    let r = XFrameOptionsChecker.check(&common::headers(&[("x-frame-options", "DENY")]));
    common::assert_golden(&serde_json::to_value(r).unwrap(), "x_frame_options/deny.json");
}

#[test]
fn xfo_allowall() {
    let r = XFrameOptionsChecker.check(&common::headers(&[("x-frame-options", "ALLOWALL")]));
    common::assert_golden(&serde_json::to_value(r).unwrap(), "x_frame_options/allowall.json");
}

#[test]
fn xfo_allow_from() {
    let r = XFrameOptionsChecker.check(&common::headers(&[(
        "x-frame-options",
        "ALLOW-FROM https://example.com",
    )]));
    common::assert_golden(&serde_json::to_value(r).unwrap(), "x_frame_options/allow_from.json");
}

// ── Referrer-Policy ──────────────────────────────────────────────────────────

#[test]
fn referrer_policy_missing() {
    let r = ReferrerPolicyChecker.check(&common::headers(&[]));
    common::assert_golden(
        &serde_json::to_value(r).unwrap(),
        "referrer_policy/missing.json",
    );
}

#[test]
fn referrer_policy_strict_origin() {
    let r = ReferrerPolicyChecker.check(&common::headers(&[(
        "referrer-policy",
        "strict-origin-when-cross-origin",
    )]));
    common::assert_golden(
        &serde_json::to_value(r).unwrap(),
        "referrer_policy/strict_origin.json",
    );
}

#[test]
fn referrer_policy_unsafe_url() {
    let r = ReferrerPolicyChecker.check(&common::headers(&[("referrer-policy", "unsafe-url")]));
    common::assert_golden(
        &serde_json::to_value(r).unwrap(),
        "referrer_policy/unsafe_url.json",
    );
}

// ── Cache-Control ─────────────────────────────────────────────────────────────

#[test]
fn cache_control_missing() {
    let r = CacheControlChecker.check(&common::headers(&[]));
    common::assert_golden(
        &serde_json::to_value(r).unwrap(),
        "cache_control/missing.json",
    );
}

#[test]
fn cache_control_no_store() {
    let r = CacheControlChecker.check(&common::headers(&[("cache-control", "no-store")]));
    common::assert_golden(
        &serde_json::to_value(r).unwrap(),
        "cache_control/no_store.json",
    );
}

// ── Server (bad header) ───────────────────────────────────────────────────────

#[test]
fn server_absent() {
    let r = ServerChecker.check(&common::headers(&[]));
    common::assert_golden(&serde_json::to_value(r).unwrap(), "server/absent.json");
}

#[test]
fn server_with_version() {
    let r = ServerChecker.check(&common::headers(&[("server", "Apache/2.4.51")]));
    common::assert_golden(&serde_json::to_value(r).unwrap(), "server/with_version.json");
}

#[test]
fn server_without_version() {
    let r = ServerChecker.check(&common::headers(&[("server", "nginx")]));
    common::assert_golden(&serde_json::to_value(r).unwrap(), "server/without_version.json");
}

// ── Deprecated headers ────────────────────────────────────────────────────────

#[test]
fn xxss_protection_absent() {
    let r = XXssProtectionChecker.check(&common::headers(&[]));
    common::assert_golden(
        &serde_json::to_value(r).unwrap(),
        "deprecated/xxss_absent.json",
    );
}

#[test]
fn xxss_protection_present() {
    let r =
        XXssProtectionChecker.check(&common::headers(&[("x-xss-protection", "1; mode=block")]));
    common::assert_golden(
        &serde_json::to_value(r).unwrap(),
        "deprecated/xxss_present.json",
    );
}

#[test]
fn public_key_pins_present() {
    let r = PublicKeyPinsChecker.check(&common::headers(&[(
        "public-key-pins",
        "pin-sha256=\"abc\"; max-age=5184000",
    )]));
    common::assert_golden(
        &serde_json::to_value(r).unwrap(),
        "deprecated/public_key_pins_present.json",
    );
}
