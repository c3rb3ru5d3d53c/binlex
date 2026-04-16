ARG UBUNTU_IMAGE=ubuntu:24.04

FROM ${UBUNTU_IMAGE} AS python-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        gnupg \
        libprotobuf-dev \
        libssl-dev \
        lsb-release \
        pkg-config \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv \
        protobuf-compiler \
        software-properties-common \
        wget \
    && wget -q https://apt.llvm.org/llvm.sh \
    && chmod +x llvm.sh \
    && ./llvm.sh 22 \
    && apt-get install -y --no-install-recommends llvm-22-dev clang-22 libclang-common-22-dev libpolly-22-dev \
    && rm -f llvm.sh \
    && rm -rf /var/lib/apt/lists/*

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain 1.94.0

ENV LLVM_SYS_221_PREFIX=/usr/lib/llvm-22
ENV PATH=/usr/lib/llvm-22/bin:/root/.cargo/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
ENV PROTOC_INCLUDE=/usr/include

WORKDIR /app

RUN python3 -m pip install --break-system-packages --no-cache-dir maturin[patchelf]

COPY . .

RUN mkdir -p /tmp/binlex-wheels \
    && python3 -m maturin build --manifest-path bindings/python/Cargo.toml --release --out /tmp/binlex-wheels

FROM ${UBUNTU_IMAGE} AS mcp-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        gnupg \
        libprotobuf-dev \
        libssl-dev \
        lsb-release \
        pkg-config \
        protobuf-compiler \
        software-properties-common \
        wget \
    && wget -q https://apt.llvm.org/llvm.sh \
    && chmod +x llvm.sh \
    && ./llvm.sh 22 \
    && apt-get install -y --no-install-recommends llvm-22-dev clang-22 libclang-common-22-dev libpolly-22-dev \
    && rm -f llvm.sh \
    && rm -rf /var/lib/apt/lists/*

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain 1.94.0

ENV LLVM_SYS_221_PREFIX=/usr/lib/llvm-22
ENV PATH=/usr/lib/llvm-22/bin:/root/.cargo/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
ENV PROTOC_INCLUDE=/usr/include

WORKDIR /app

COPY . .

RUN set -eux; \
    cargo build --release -p binlex-mcp --bin binlex-mcp; \
    for manifest in $(find crates/binlex_processors -mindepth 2 -maxdepth 2 -name Cargo.toml | sort); do \
        cargo build --release --manifest-path "$manifest"; \
    done; \
    mkdir -p /tmp/binlex-processors; \
    for path in /app/target/release/binlex-processor-*; do \
        [ -f "$path" ] || continue; \
        [ -x "$path" ] || continue; \
        cp "$path" /tmp/binlex-processors/; \
    done

FROM ${UBUNTU_IMAGE}

ARG BINLEX_IMAGE_SOURCE=https://github.com/c3rb3ru5d3d53c/binlex
ARG BINLEX_IMAGE_VERSION=dev
ARG BINLEX_IMAGE_REVISION=unknown

LABEL org.opencontainers.image.source="${BINLEX_IMAGE_SOURCE}"
LABEL org.opencontainers.image.version="${BINLEX_IMAGE_VERSION}"
LABEL org.opencontainers.image.revision="${BINLEX_IMAGE_REVISION}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libgcc-s1 \
        libmagic1 \
        libstdc++6 \
        python3 \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data/binlex-mcp /opt/binlex/processors /root/.config/binlex /root/.local/share/binlex/processors /samples

COPY --from=python-builder /tmp/binlex-wheels /tmp/binlex-wheels

RUN python3 -m venv /opt/binlex-venv \
    && /opt/binlex-venv/bin/pip install --no-cache-dir /tmp/binlex-wheels/binlex-*.whl \
    && /opt/binlex-venv/bin/pip install --no-cache-dir \
        requests==2.33.0 \
        yara-python==4.5.4 \
        python-magic==0.4.27 \
    && rm -rf /tmp/binlex-wheels

WORKDIR /app

COPY --from=mcp-builder /app/target/release/binlex-mcp /usr/local/bin/binlex-mcp
COPY --from=mcp-builder /tmp/binlex-processors/ /opt/binlex/processors/
COPY --from=mcp-builder /tmp/binlex-processors/ /root/.local/share/binlex/processors/
COPY --from=mcp-builder /app/crates/binlex_tools/binlex-mcp/skills /opt/binlex-mcp/skills

ENV PATH=/opt/binlex-venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV BINLEX_MCP_LISTEN=0.0.0.0
ENV BINLEX_MCP_PORT=3000
ENV BINLEX_MCP_BASE_URL=
ENV BINLEX_MCP_CONFIG=/root/.config/binlex/binlex-mcp.toml
ENV BINLEX_MCP_SAMPLES=/root/.local/share/binlex/samples

EXPOSE 3000

CMD ["sh", "-lc", "mkdir -p /data/binlex-mcp /root/.config/binlex /root/.local/share/binlex/processors \"${BINLEX_MCP_SAMPLES}\" && cp -an /opt/binlex/processors/. /root/.local/share/binlex/processors/ && if [ ! -f \"${BINLEX_MCP_CONFIG}\" ]; then init_source=\"${BINLEX_MCP_INIT_SOURCES:-/opt/binlex-mcp/skills}\"; binlex-mcp init --yes --config \"${BINLEX_MCP_CONFIG}\" \"${init_source}\"; fi && exec binlex-mcp serve --config \"${BINLEX_MCP_CONFIG}\" --samples \"${BINLEX_MCP_SAMPLES}\" --listen \"${BINLEX_MCP_LISTEN}\" --port \"${BINLEX_MCP_PORT}\""]
