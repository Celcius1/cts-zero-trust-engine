# ==============================================================================
# CTS ZERO TRUST ENGINE - C++ API BUILDER
# (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.
# ==============================================================================
FROM ubuntu:24.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|http://archive.ubuntu.com/ubuntu/|http://au.archive.ubuntu.com/ubuntu/|g' /etc/apt/sources.list.d/ubuntu.sources
# NEW: Added libpqxx-dev to the builder dependencies
RUN apt-get update && apt-get install -y cmake g++ wget pkg-config libpq-dev libpqxx-dev libsodium-dev libpoco-dev ca-certificates

WORKDIR /build_env
COPY CMakeLists.txt ./
COPY src/ ./src/

RUN mkdir build && cd build && cmake .. && make -j$(nproc)

# --- Final Runtime Stage ---
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|http://archive.ubuntu.com/ubuntu/|http://au.archive.ubuntu.com/ubuntu/|g' /etc/apt/sources.list.d/ubuntu.sources && \
    apt-get update && apt-get install -y \
    libpq5 \
    libpqxx-dev \
    libsodium23 \
    libpoco-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build_env/build/cts_api .
# --- HARD-BAKE THE WEB FILES INTO THE IMAGE ---
COPY ./public /app/public 
# ----------------------------------------------
CMD ["./cts_api"]