#!/usr/bin/env bash
# run_tests.sh - run unit/golden tests and all fuzz targets, then report results.
#
# Usage:
#   ./run_tests.sh               # fuzz each target for 30 seconds (default)
#   ./run_tests.sh 60            # custom fuzz duration in seconds
#   SKIP_FUZZ=1 ./run_tests.sh   # unit/golden tests only
#
# Requirements for fuzz targets: nightly Rust + cargo-fuzz
#   rustup toolchain install nightly
#   cargo install cargo-fuzz

set -euo pipefail

FUZZ_SECONDS=${1:-30}
failures=()

step() {
    local label="$1"; shift
    echo ""
    echo "══ $label ══"
    if "$@"; then
        echo "  PASSED: $label"
    else
        echo "  FAILED: $label"
        failures+=("$label")
    fi
}

# Unit & Golden
step "Unit / golden tests" cargo test

# Fuzz target
if [[ -z "${SKIP_FUZZ:-}" ]]; then
    for target in fuzz_normalize fuzz_hsts fuzz_csp fuzz_x_frame_options; do
        step "Fuzz: $target (${FUZZ_SECONDS}s)" \
            cargo +nightly fuzz run "$target" "fuzz/corpus/$target" -- "-max_total_time=$FUZZ_SECONDS"
    done
fi

# Summary 
echo ""
printf -- '-%.0s' {1..60}; echo ""
if [ ${#failures[@]} -eq 0 ]; then
    echo "All checks passed."
    exit 0
else
    echo "${#failures[@]} check(s) failed:"
    for f in "${failures[@]}"; do
        echo "  - $f"
    done
    exit 1
fi
