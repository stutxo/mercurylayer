# Start with Ubuntu as base image
FROM ubuntu:22.04 AS builder

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install essential packages
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    curl \
    git \
    ninja-build \
    pkg-config \
    tar \
    unzip \
    zip \
    libpq-dev \  
    autoconf \ 
    automake \ 
    libtool \ 
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /app

# Install vcpkg
RUN git clone https://github.com/Microsoft/vcpkg.git /opt/vcpkg && \
    /opt/vcpkg/bootstrap-vcpkg.sh -disableMetrics

# Add vcpkg to PATH
ENV PATH="/opt/vcpkg:${PATH}"

# Set vcpkg root
ENV VCPKG_ROOT=/opt/vcpkg

ARG LOCKBOX_ENABLE_TEST_RNG=OFF

# Copy your project files
COPY . .

# Create build directory and run cmake
RUN mkdir -p build && cd build
RUN cd build && cmake --preset=vcpkg -DLOCKBOX_ENABLE_TEST_RNG=${LOCKBOX_ENABLE_TEST_RNG} ..
RUN cd build && cmake --build .
RUN test -s ./build/MercuryLockbox && test -s ./build/libLockboxLibrary.a

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/build/MercuryLockbox /usr/local/bin/MercuryLockbox

CMD ["/usr/local/bin/MercuryLockbox"]
