ARG BITCOIN_INQUISITION_REPO=https://github.com/bitcoin-inquisition/bitcoin.git
ARG BITCOIN_INQUISITION_COMMIT=f5365867662091c2dbf1b2d438b8bb477a3dcb6f

FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    git \
    libboost-dev \
    libevent-dev \
    libsqlite3-dev \
    ninja-build \
    pkg-config \
    python3 \
    && rm -rf /var/lib/apt/lists/*

ARG BITCOIN_INQUISITION_REPO
ARG BITCOIN_INQUISITION_COMMIT

RUN git init /src \
    && git -C /src remote add origin "$BITCOIN_INQUISITION_REPO" \
    && git -C /src fetch --depth=1 origin "$BITCOIN_INQUISITION_COMMIT" \
    && git -C /src checkout --detach FETCH_HEAD

RUN cmake -S /src -B /build -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/opt/bitcoin-inquisition \
    -DBUILD_DAEMON=ON \
    -DBUILD_CLI=ON \
    -DBUILD_GUI=OFF \
    -DBUILD_TESTS=OFF \
    -DBUILD_BENCH=OFF \
    -DBUILD_FUZZ_BINARY=OFF \
    -DENABLE_WALLET=ON \
    -DWITH_SQLITE=ON \
    -DWITH_BDB=OFF \
    -DWITH_ZMQ=OFF \
    -DINSTALL_MAN=OFF \
    && cmake --build /build --target install --parallel

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libevent-2.1-7 \
    libevent-extra-2.1-7 \
    libevent-pthreads-2.1-7 \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/bitcoin-inquisition/bin/bitcoind /usr/local/bin/bitcoind
COPY --from=builder /opt/bitcoin-inquisition/bin/bitcoin-cli /usr/local/bin/bitcoin-cli

EXPOSE 18443 18444

ENTRYPOINT ["bitcoind"]
