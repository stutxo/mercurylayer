# syntax=docker/dockerfile:1.7

FROM rust:1.92-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang nodejs npm \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown \
    && cargo install wasm-pack --version 0.13.1 --locked

ENV CC_wasm32_unknown_unknown=clang
WORKDIR /workspace
COPY . .
RUN web-wallet/build.sh \
    && test -s web-wallet/pkg/mercury_web_wallet_bg.wasm \
    && test -s web-wallet/pkg/mercury_web_wallet.js

FROM nginx:1.27-alpine
COPY web-wallet/nginx.conf /etc/nginx/conf.d/default.conf
COPY web-wallet/index.html web-wallet/favicon.svg web-wallet/web.css web-wallet/web.js /usr/share/nginx/html/
COPY --from=builder /workspace/web-wallet/pkg /usr/share/nginx/html/pkg
EXPOSE 8080
