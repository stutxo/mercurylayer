# Use an explicit Rust toolchain that supports current dependency editions.
FROM rust:1.92-bullseye AS builder

# Install Rust, protobuf compiler, and library dependencies
RUN apt-get update && apt-get install -y curl build-essential protobuf-compiler libprotobuf-dev pkg-config libssl-dev
ENV RUSTUP_TOOLCHAIN=1.92.0

# Create a working directory
WORKDIR /mercurylayer

RUN echo "[workspace]\nmembers = [\"server\", \"lib\"]" > ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock

# Copy the server source code
COPY ./server ./server
# Remove Settings.toml file
RUN rm -f ./server/Settings.toml
COPY ./lib ./lib
COPY ./Rocket.toml ./server/Rocket.toml

# Make sure to copy Cargo.lock
COPY ./server/Cargo.lock ./server/Cargo.lock

WORKDIR /mercurylayer/server

# RUN cargo build --verbose

# # Build your Rust project. Since the source files are now present,
# # the Rust compiler should be able to find and compile them.
RUN CARGO_TARGET_DIR=target  cargo build --release

# # Command to run the server by default when the container starts
CMD ["cargo", "run", "--bin", "mercury-server"]
