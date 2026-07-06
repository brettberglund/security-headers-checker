# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo build               # compile (debug)
cargo build --release     # compile (release)
cargo run -- <url>        # run the CLI against a URL
cargo test                # run all tests
cargo test <test_name>    # run a single test by name
cargo clippy              # lint
cargo fmt                 # format
```

## Architecture

The pipeline, in order: **normalize → HTTP request → extract headers → score/grade → report**

`src/lib.rs` — library root; exports `run()` which drives the full pipeline.  
`src/main.rs` — binary entry point; parses CLI args, calls `lib::run()`.  
`src/normalize.rs` — URL normalization (e.g. prepends `https://` if missing).  
`src/http_request.rs` — HTTP client, follows redirects, returns a `HeaderMap`. (stub)  
`src/header_checker.rs` — core types: `HeaderChecker` trait, `CheckResult`, `CheckStatus`, `Severity`.

### HeaderChecker pattern
Each security header gets its own struct that implements the `HeaderChecker` trait:
```rust
pub trait HeaderChecker: Send + Sync {
    fn name(&self) -> &str;
    fn check(&self, headers: &HeaderMap) -> CheckResult;
}
```
A runner collects all checker instances, iterates the `HeaderMap`, and aggregates `CheckResult`s for scoring.

### Scoring grades
`A+` → all headers present and correctly configured  
`A` → all critical headers present, minor warnings only  
`B` → one high-severity header missing or medium misconfigurations  
`C` → multiple important headers missing  
`D` → significant gaps, information leakage  
`F` → critical misconfigurations or most headers absent  

### Headers under scrutiny
**Checked (required):** HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP, Cache-Control  
**Flagged as bad (info leakage):** `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`  
**Flagged as deprecated:** `X-XSS-Protection`, `Public-Key-Pins`

CSP gets deeper analysis: `unsafe-inline` / `unsafe-eval` are high severity; missing `default-src` or `frame-ancestors` are flagged; `default-src *` is medium.

## Known issues / stubs
- `src/http_request.rs` is empty — HTTP client not yet implemented.
- `src/main.rs` imports `http_header_checker::run` but the crate is named `security-headers-checker` in `Cargo.toml`; this needs to be reconciled.
- No `[dependencies]` section in `Cargo.toml` yet; will need `reqwest` (async HTTP) and `http` (for `HeaderMap`).
