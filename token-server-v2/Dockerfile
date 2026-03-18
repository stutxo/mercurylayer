# First stage: builder
FROM rust:1.92-bullseye AS builder
RUN apt-get update && apt-get install -y curl build-essential protobuf-compiler libprotobuf-dev pkg-config libssl-dev
ENV RUSTUP_TOOLCHAIN=1.92.0
WORKDIR /mercurylayer
RUN echo "[workspace]\nmembers = [\"token-server-v2\"]" > ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
COPY ./token-server-v2 ./token-server-v2
COPY ./token-server-v2/Rocket.toml ./token-server-v2/Rocket.toml
WORKDIR /mercurylayer/token-server-v2
RUN CARGO_TARGET_DIR=target cargo build --release

# Second stage: final image
FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y ca-certificates
WORKDIR /app
# Copy the built binary from builder stage
COPY --from=builder /mercurylayer/token-server-v2/target/release/token-server-v2 .
COPY --from=builder /mercurylayer/token-server-v2/Rocket.toml .
EXPOSE 8001
CMD ["./token-server-v2"]
