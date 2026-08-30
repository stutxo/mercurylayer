# syntax=docker/dockerfile:1.7

FROM ubuntu:22.04 AS builder

ARG TARGETARCH
ARG VCPKG_COMMIT=6046e48163a26252f7a8f4aa036cbdd9eb793c20
ARG LOCKBOX_ENABLE_TEST_RNG=OFF
ARG LOCKBOX_ENABLE_GOOGLE_KMS=OFF
ARG LOCKBOX_DATABASE_BACKEND=postgres
ARG LOCKBOX_BUILD_TESTS=OFF
ENV DEBIAN_FRONTEND=noninteractive
ENV VCPKG_ROOT=/opt/vcpkg
ENV VCPKG_DISABLE_METRICS=1
ENV VCPKG_FORCE_SYSTEM_BINARIES=1
ENV PATH="${VCPKG_ROOT}:${PATH}"

RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    build-essential \
    cmake \
    curl \
    git \
    libpq-dev \
    libsqlite3-dev \
    libtool \
    ninja-build \
    pkg-config \
    tar \
    unzip \
    zip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN git clone https://github.com/Microsoft/vcpkg.git /opt/vcpkg && \
    git -C /opt/vcpkg checkout "$VCPKG_COMMIT" && \
    /opt/vcpkg/bootstrap-vcpkg.sh -disableMetrics

COPY vcpkg.json vcpkg-configuration.json ./
COPY vcpkg-triplets ./vcpkg-triplets

RUN case "$TARGETARCH" in \
      amd64) echo x64-linux-release > /tmp/vcpkg-triplet ;; \
      arm64) echo arm64-linux-release > /tmp/vcpkg-triplet ;; \
      *) echo "unsupported Docker target architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac

RUN --mount=type=cache,target=/root/.cache/vcpkg \
    --mount=type=cache,target=/opt/vcpkg/downloads \
    vcpkg install --triplet "$(cat /tmp/vcpkg-triplet)" --overlay-triplets=/app/vcpkg-triplets

COPY CMakeLists.txt CMakePresets.json ./
COPY cmake ./cmake
COPY include ./include
COPY src ./src
COPY tests ./tests

RUN --mount=type=cache,target=/root/.cache/vcpkg \
    --mount=type=cache,target=/opt/vcpkg/downloads \
    --mount=type=cache,target=/app/build/_deps \
    --mount=type=cache,target=/app/build/secp256k1 \
    sh -eux -c ' \
      manifest_features=""; \
      case "$LOCKBOX_ENABLE_GOOGLE_KMS" in \
        ON|on|1|true|TRUE|yes|YES) manifest_features="-DVCPKG_MANIFEST_FEATURES=google-kms" ;; \
      esac; \
      cmake --preset=vcpkg \
        -DVCPKG_TARGET_TRIPLET="$(cat /tmp/vcpkg-triplet)" \
        -DLOCKBOX_ENABLE_TEST_RNG="$LOCKBOX_ENABLE_TEST_RNG" \
        -DLOCKBOX_ENABLE_GOOGLE_KMS="$LOCKBOX_ENABLE_GOOGLE_KMS" \
        -DLOCKBOX_DATABASE_BACKEND="$LOCKBOX_DATABASE_BACKEND" \
        -DLOCKBOX_BUILD_TESTS="$LOCKBOX_BUILD_TESTS" \
        $manifest_features; \
      cmake --build build; \
      case "$LOCKBOX_BUILD_TESTS" in \
        ON|on|1|true|TRUE|yes|YES) ctest --test-dir build --output-on-failure ;; \
      esac; \
      test -s build/MercuryLockbox; \
      test -s build/libLockboxLibrary.a; \
    '

FROM ubuntu:22.04

ARG LOCKBOX_REQUIRE_AUTH=1

ENV DEBIAN_FRONTEND=noninteractive \
    KEY_MANAGER=filesystem \
    SEED_FILEPATH=/data/lockbox.seed \
    LOCKBOX_DATABASE_PATH=/data/lockbox.sqlite3 \
    LOCKBOX_PORT=18080 \
    LOCKBOX_BIND_ADDRESS=0.0.0.0 \
    LOCKBOX_REQUIRE_AUTH=${LOCKBOX_REQUIRE_AUTH} \
    PGSSLROOTCERT=/etc/ssl/certs/ca-certificates.crt

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpq5 \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/build/MercuryLockbox /usr/local/bin/MercuryLockbox
RUN install -d -m 0700 /data
EXPOSE 18080
CMD ["/usr/local/bin/MercuryLockbox"]
