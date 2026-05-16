# Base
FROM rust:1-slim-bookworm AS base

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev g++ \
    && rm -rf /var/lib/apt/lists/* \
    && rustup toolchain install nightly --profile minimal \
    && cargo install cargo-fuzz

WORKDIR /app

FROM base AS builder

# Compile dependencies using a stub crate so this layer is cached separately
# from source changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo 'pub fn _stub() {}' > src/lib.rs \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src \
    && find target/release -name '*security_headers_checker*' -delete \
    && rm -rf target/release/.fingerprint/security-headers-checker-*

COPY src/ src/
COPY tests/ tests/
COPY fuzz/ fuzz/
COPY run_tests.sh ./
RUN chmod +x run_tests.sh \
    && cargo build --release

# cli - minimal runtime image with just the binary
#
# Build:  docker build --target cli -t security-headers-checker .
# Run:    docker run --rm security-headers-checker https://example.com
FROM debian:bookworm-slim AS cli

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/security-headers-checker /usr/local/bin/

ENTRYPOINT ["security-headers-checker"]

# test - unit/golden tests + fuzz targets (Linux; ASAN works here)
#
# Build:  docker build --target test -t security-headers-checker-test .
# Run:    docker run --rm security-headers-checker-test          # 30 s fuzz
#         docker run --rm -e FUZZ_SECONDS=60 security-headers-checker-test
#         docker run --rm -e SKIP_FUZZ=1 security-headers-checker-test
FROM builder AS test

CMD ["./run_tests.sh"]
