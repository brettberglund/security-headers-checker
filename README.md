# security-headers-checker

A CLI tool that scans URLs for missing or misconfigured HTTP security headers and produces a scored report.

## Usage

```
security-headers-checker <url>
```

The URL is normalized before the request (e.g. `example.com` becomes `https://example.com`). Redirects are followed automatically.

## Pipeline

```
URL input → normalize → HTTP request → extract headers → score/grade → report
```

Each header has its own checker implementing the `HeaderChecker` trait. A runner collects all checkers, iterates the response `HeaderMap`, and aggregates results for evaluation.

## Checked Headers

### Required (missing = finding)

| Header | Notes |
|---|---|
| `Strict-Transport-Security` | Requires `max-age` ≥ 31536000; `includeSubDomains` and `preload` checked |
| `Content-Security-Policy` | `unsafe-inline`/`unsafe-eval` = high; missing `default-src` or `frame-ancestors` flagged; `default-src *` = medium |
| `X-Frame-Options` | Valid: `DENY`, `SAMEORIGIN`; superseded by CSP `frame-ancestors` but checked for compatibility |
| `X-Content-Type-Options` | Must be `nosniff`; missing = medium |
| `Referrer-Policy` | `unsafe-url` = medium; recommends `strict-origin-when-cross-origin` or stricter |
| `Permissions-Policy` | Missing = low; overly permissive = medium |
| `Cross-Origin-Opener-Policy` | Missing = low–medium |
| `Cross-Origin-Embedder-Policy` | Missing = informational unless COOP is set |
| `Cross-Origin-Resource-Policy` | Missing = low |
| `Cache-Control` | `no-store` expected on authenticated pages; missing = medium |

### Bad (information leakage)

| Header | Severity |
|---|---|
| `Server` | Low–medium |
| `X-Powered-By` | Low |
| `X-AspNet-Version` | Low |
| `X-AspNetMvc-Version` | Low |

### Deprecated (should be removed)

| Header | Notes |
|---|---|
| `X-XSS-Protection` | Counterproductive in some browsers; should be removed or set to `0` |
| `Public-Key-Pins` | Deprecated; removal recommended |

## Grades

| Grade | Meaning |
|---|---|
| `A+` | All headers present and correctly configured, no information leakage |
| `A` | All critical headers present, minor warnings only |
| `B` | One high-severity header missing or medium misconfigurations present |
| `C` | Multiple important headers missing |
| `D` | Significant gaps, information leakage present |
| `F` | Missing most security headers or critical misconfigurations |

## Build

```bash
cargo build           # debug
cargo build --release # release
cargo test            # run tests
cargo clippy          # lint
```

## License

AGPL-3.0
