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
cargo test            # run all tests
cargo clippy          # lint
cargo fmt             # format
```

## Container

The `Dockerfile` is multi-stage and produces two named targets.

### `cli` — minimal runtime image

Contains only the release binary and its runtime dependencies (~100 MB).

```bash
# Build
docker build --target cli -t security-headers-checker .

# Run
docker run --rm security-headers-checker https://example.com
```

### `test` — full test environment

Built on the `builder` stage; includes the Rust toolchain, `cargo-fuzz`, nightly, and all source/test/fuzz files. Runs `run_tests.sh` by default.

```bash
# Build
docker build --target test -t security-headers-checker-test .

# Run (30 s fuzz, default)
docker run --rm security-headers-checker-test

# Custom fuzz duration
docker run --rm -e FUZZ_SECONDS=60 security-headers-checker-test

# Skip fuzz, unit/golden tests only
docker run --rm -e SKIP_FUZZ=1 security-headers-checker-test
```

## Tests

### Run everything at once

Two wrapper scripts run unit/golden tests and all fuzz targets in sequence and print a pass/fail summary.

**Windows (PowerShell):**

```powershell
.\run_tests.ps1                  # fuzz each target for 30 s (default)
.\run_tests.ps1 -FuzzSeconds 60  # custom fuzz duration
.\run_tests.ps1 -SkipFuzz        # unit/golden tests only
```

**Linux / macOS (bash):**

```bash
chmod +x run_tests.sh
./run_tests.sh                   # fuzz each target for 30 s (default)
./run_tests.sh 60                # custom fuzz duration
SKIP_FUZZ=1 ./run_tests.sh       # unit/golden tests only
```

Both scripts exit `0` when all checks pass and `1` otherwise, making them suitable for CI.

### Run in the test container

The `test` Docker target provides a reproducible Linux environment with nightly Rust and ASAN support, which is required for fuzz testing on Linux.

```bash
docker build --target test -t security-headers-checker-test .

docker run --rm security-headers-checker-test                       # 30 s fuzz (default)
docker run --rm -e FUZZ_SECONDS=60 security-headers-checker-test    # custom fuzz duration
docker run --rm -e SKIP_FUZZ=1 security-headers-checker-test        # unit/golden tests only
```

### Unit / golden tests

The integration test suite lives in `tests/golden_tests.rs`. Each test drives a single header checker with a specific input and compares the serialized `CheckResult` against a golden JSON fixture in `tests/golden/`.

```bash
cargo test                        # run all tests
cargo test hsts                   # run tests whose name contains "hsts"
cargo test csp_unsafe_inline      # run a single test by name
```

Golden files are the source of truth for checker output. To regenerate them after intentional behaviour changes:

```bash
# Linux / macOS
UPDATE_GOLDEN=1 cargo test

# Windows (PowerShell)
$env:UPDATE_GOLDEN=1; cargo test
```

### Common test helpers

`tests/common/mod.rs` provides two utilities used by every test:

| Helper | Purpose |
|---|---|
| `common::headers(&[("name", "value"), …])` | Builds a `HeaderMap` from key-value pairs |
| `common::assert_golden(json, "subdir/file.json")` | Compares serialised output to `tests/golden/<path>`; respects `UPDATE_GOLDEN` |

### Fuzz tests

Fuzz targets live in `fuzz/fuzz_targets/` and require [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (nightly Rust):

```bash
cargo install cargo-fuzz
```

| Target | What it fuzzes |
|---|---|
| `fuzz_normalize` | URL normalizer (`normalize_url`) |
| `fuzz_hsts` | HSTS header checker |
| `fuzz_csp` | CSP header checker |
| `fuzz_x_frame_options` | X-Frame-Options checker |

Run a target (from the repo root):

```bash
cargo fuzz run fuzz_normalize
cargo fuzz run fuzz_hsts
cargo fuzz run fuzz_csp
cargo fuzz run fuzz_x_frame_options
```

Seed corpus entries are in `fuzz/corpus/<target>/`. Pass a corpus directory to start from the seeds rather than from scratch:

```bash
cargo fuzz run fuzz_normalize fuzz/corpus/fuzz_normalize
```

## License

AGPL-3.0
