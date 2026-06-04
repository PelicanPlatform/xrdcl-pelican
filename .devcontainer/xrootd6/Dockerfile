FROM almalinux:10

# Enable EPEL and CRB (CodeReady Builder) for dev headers we need.
RUN dnf install -y dnf-plugins-core epel-release && \
    dnf config-manager --set-enabled crb && \
    dnf clean all

# Build deps for both XRootD and xrdcl-pelican.  scitokens-cpp-devel is required
# to build XRootD's XrdAccSciTokens authorization plugin, which the Pelican
# integration-test fixture loads (`ofs.authlib ++ libXrdAccSciTokens.so`) when it
# stands up an origin; without it the origin fails to initialize and the
# integration tests cannot run.
RUN dnf install -y \
        cmake \
        diffutils \
        gcc-c++ \
        git \
        golang \
        libcurl-devel \
        libuuid-devel \
        nlohmann-json-devel \
        ninja-build \
        openssl-devel \
        pkgconf-pkg-config \
        scitokens-cpp-devel \
        sqlite-devel \
        tinyxml2-devel \
        zlib-devel \
    && dnf clean all

# Build XRootD 6.0.2 from source with ASAN so we can debug the plugin against
# the same instrumentation as production.  Upstream v6 already contains the
# (former) XrdClCurl and XrdClS3 plugins, so xrdcl-pelican only needs to build
# its Pelican plugin against this XRootD.  ENABLE_SCITOKENS builds the
# XrdAccSciTokens plugin (needs scitokens-cpp-devel) used by the integration tests.
RUN git clone --depth 1 --branch v6.0.2 https://github.com/xrootd/xrootd.git /tmp/xrootd && \
    cd /tmp/xrootd && \
    mkdir -p build && cd build && \
    cmake .. \
        -DCMAKE_INSTALL_PREFIX=/usr/local/xrootd \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DENABLE_ASAN=TRUE \
        -DENABLE_PYTHON=OFF \
        -DENABLE_SCITOKENS=TRUE && \
    make -j$(nproc) install && \
    rm -rf /tmp/xrootd

# Some integration tests drive a real HTTP server with this tiny load tester.
RUN go install github.com/bbockelm/go-wrk@92dbe19 && \
    cp ~/go/bin/go-wrk /usr/local/xrootd/bin/ && \
    rm -rf ~/go

# XRootD integration tests expect an `xrootd` system user.
RUN useradd -r -s /sbin/nologin xrootd

ENV PATH="/usr/local/xrootd/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/xrootd/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
ENV CMAKE_PREFIX_PATH="/usr/local/xrootd"
