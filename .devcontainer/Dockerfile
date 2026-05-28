FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies (matching CI workflow)
RUN apt-get update && apt-get install -y \
    cmake \
    g++ \
    git \
    golang-go \
    libcurl4-openssl-dev \
    libcurl4 \
    libgtest-dev \
    nlohmann-json3-dev \
    libscitokens-dev \
    libsqlite3-dev \
    libssl-dev \
    libtinyxml2-dev \
    libz-dev \
    ninja-build \
    pkg-config \
    uuid-dev \
    && rm -rf /var/lib/apt/lists/*

# Build XRootD from PelicanPlatform's v5.8.4-pelican branch with ASAN
RUN git clone https://github.com/xrootd/xrootd.git /tmp/xrootd && \
    cd /tmp/xrootd && \
    git remote add github_pelican https://github.com/PelicanPlatform/xrootd.git && \
    git fetch github_pelican && \
    git checkout -b v5.8.4-pelican -t github_pelican/v5.8.4-pelican && \
    mkdir -p build && cd build && \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local/xrootd -DENABLE_ASAN=TRUE && \
    make -j$(nproc) install && \
    rm -rf /tmp/xrootd

# Install the load tester (used by some integration tests)
RUN go install github.com/bbockelm/go-wrk@92dbe19 && \
    cp ~/go/bin/go-wrk /usr/local/xrootd/bin/ && \
    rm -rf ~/go

# Pelican integration tests require an 'xrootd' user to exist
RUN useradd -r -s /sbin/nologin xrootd

ENV PATH="/usr/local/xrootd/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/xrootd/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
