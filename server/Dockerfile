# syntax=docker/dockerfile:1.7

FROM rust:1.92-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libprotobuf-dev \
        libssl-dev \
        pkg-config \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_TOOLCHAIN=1.92.0 \
    CARGO_TARGET_DIR=/mercurylayer/server/target

WORKDIR /mercurylayer

COPY Cargo.toml ./Cargo.toml
COPY Cargo.lock ./Cargo.lock
COPY clients/apps/rust/Cargo.toml ./clients/apps/rust/Cargo.toml
COPY clients/libs/rust/Cargo.toml ./clients/libs/rust/Cargo.toml
COPY clients/tests/rust/Cargo.toml ./clients/tests/rust/Cargo.toml
COPY lib/Cargo.toml ./lib/Cargo.toml
COPY server/Cargo.toml ./server/Cargo.toml
COPY token-server/Cargo.toml ./token-server/Cargo.toml
COPY web-wallet/Cargo.toml ./web-wallet/Cargo.toml
RUN mkdir -p \
        clients/apps/rust/src \
        clients/libs/rust/src \
        clients/tests/rust/src \
        lib/src \
        server/src \
        token-server/src \
        web-wallet/src \
    && printf 'fn main() {}\n' > clients/apps/rust/src/main.rs \
    && printf '// dependency cache placeholder\n' > clients/libs/rust/src/lib.rs \
    && printf 'fn main() {}\n' > clients/tests/rust/src/main.rs \
    && printf '// dependency cache placeholder\n' > lib/src/lib.rs \
    && printf 'fn main() {}\n' > server/src/main.rs \
    && printf 'fn main() {}\n' > token-server/src/main.rs \
    && printf '// dependency cache placeholder\n' > web-wallet/src/lib.rs \
    && cargo build --release --locked --package mercury-server --bin mercury-server

COPY server/src ./server/src
COPY server/migrations ./server/migrations
COPY lib/src ./lib/src
RUN find server/src lib/src -type f -exec touch {} + \
    && cargo build --release --locked --package mercury-server --bin mercury-server \
    && test -x server/target/release/mercury-server

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 mercury \
    && useradd --system --uid 10001 --gid mercury --home-dir /nonexistent mercury

WORKDIR /mercurylayer/server
COPY --chown=mercury:mercury --from=builder /mercurylayer/server/target/release/mercury-server ./target/release/mercury-server
COPY --chown=mercury:mercury Rocket.toml ./Rocket.toml

USER mercury
EXPOSE 8000
CMD ["./target/release/mercury-server"]
