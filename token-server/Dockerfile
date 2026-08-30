# First stage: builder
FROM rust:1.92-bullseye AS builder
RUN apt-get update && apt-get install -y curl build-essential protobuf-compiler libprotobuf-dev pkg-config libssl-dev
ENV RUSTUP_TOOLCHAIN=1.92.0
WORKDIR /mercurylayer
RUN printf '%s\n' \
  '[workspace]' \
  'members = ["token-server"]' \
  'resolver = "2"' \
  '' \
  '[patch.crates-io]' \
  'secp256k1 = { git = "https://github.com/w0xlt/rust-secp256k1.git", branch = "mercury-blinded-musig-port" }' \
  > ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
COPY ./token-server ./token-server
COPY ./token-server/Rocket.toml ./token-server/Rocket.toml
WORKDIR /mercurylayer/token-server
RUN CARGO_TARGET_DIR=target cargo build --release

# Second stage: final image
FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y ca-certificates
WORKDIR /app
# Copy the built binary from builder stage
COPY --from=builder /mercurylayer/token-server/target/release/token-server .
COPY --from=builder /mercurylayer/token-server/Rocket.toml .
EXPOSE 8001
CMD ["./token-server"]
