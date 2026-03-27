ARG PYTHON_BUILD_IMAGE=python:3.12.13-bookworm
ARG PYTHON_RUNTIME_IMAGE=python:3.12.13-slim-bookworm
ARG RUST_IMAGE=rust:1.94-bookworm

ARG BINLEX_IMAGE_SOURCE=https://github.com/c3rb3ru5d3d53c/binlex
ARG BINLEX_IMAGE_VERSION=dev
ARG BINLEX_IMAGE_REVISION=unknown

FROM ${PYTHON_BUILD_IMAGE} AS binlex-python-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        libprotobuf-dev \
        pkg-config \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain 1.94.0

ENV PATH=/root/.cargo/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
ENV PROTOC_INCLUDE=/usr/include

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip maturin[patchelf]

COPY . .

RUN mkdir -p /tmp/binlex-wheels \
    && maturin build --manifest-path bindings/python/Cargo.toml --release --out /tmp/binlex-wheels

FROM ${PYTHON_RUNTIME_IMAGE} AS binlex-python

ARG BINLEX_IMAGE_SOURCE
ARG BINLEX_IMAGE_VERSION
ARG BINLEX_IMAGE_REVISION

LABEL org.opencontainers.image.source="${BINLEX_IMAGE_SOURCE}"
LABEL org.opencontainers.image.version="${BINLEX_IMAGE_VERSION}"
LABEL org.opencontainers.image.revision="${BINLEX_IMAGE_REVISION}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libgcc-s1 \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=binlex-python-builder /tmp/binlex-wheels /tmp/binlex-wheels

RUN pip install --no-cache-dir /tmp/binlex-wheels/binlex-*.whl \
    && rm -rf /tmp/binlex-wheels

WORKDIR /app

FROM ${RUST_IMAGE} AS binlex-mcp-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libprotobuf-dev \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

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

FROM binlex-python AS binlex-mcp

ARG BINLEX_IMAGE_SOURCE
ARG BINLEX_IMAGE_VERSION
ARG BINLEX_IMAGE_REVISION

LABEL org.opencontainers.image.source="${BINLEX_IMAGE_SOURCE}"
LABEL org.opencontainers.image.version="${BINLEX_IMAGE_VERSION}"
LABEL org.opencontainers.image.revision="${BINLEX_IMAGE_REVISION}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libgcc-s1 \
        libmagic1 \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data/binlex-mcp /opt/binlex/processors /root/.config/binlex /root/.local/share/binlex/processors /samples

RUN pip install --no-cache-dir \
        requests==2.33.0 \
        yara-python==4.5.4 \
        python-magic==0.4.27

WORKDIR /app

COPY --from=binlex-mcp-builder /app/target/release/binlex-mcp /usr/local/bin/binlex-mcp
COPY --from=binlex-mcp-builder /tmp/binlex-processors/ /opt/binlex/processors/
COPY --from=binlex-mcp-builder /tmp/binlex-processors/ /root/.local/share/binlex/processors/
COPY --from=binlex-mcp-builder /app/crates/binlex_tools/binlex-mcp/skills /opt/binlex-mcp/skills

ENV BINLEX_MCP_LISTEN=0.0.0.0
ENV BINLEX_MCP_PORT=3000
ENV BINLEX_MCP_BASE_URL=
ENV BINLEX_MCP_CONFIG=/root/.config/binlex/binlex-mcp.toml
ENV BINLEX_MCP_SAMPLES=/root/.local/share/binlex/samples

EXPOSE 3000

CMD ["sh", "-lc", "mkdir -p /data/binlex-mcp /root/.config/binlex /root/.local/share/binlex/processors \"${BINLEX_MCP_SAMPLES}\" && cp -an /opt/binlex/processors/. /root/.local/share/binlex/processors/ && if [ ! -f \"${BINLEX_MCP_CONFIG}\" ]; then init_source=\"${BINLEX_MCP_INIT_SOURCES:-/opt/binlex-mcp/skills}\"; binlex-mcp init --yes --config \"${BINLEX_MCP_CONFIG}\" \"${init_source}\"; fi && exec binlex-mcp serve --config \"${BINLEX_MCP_CONFIG}\" --samples \"${BINLEX_MCP_SAMPLES}\" --listen \"${BINLEX_MCP_LISTEN}\" --port \"${BINLEX_MCP_PORT}\""]

FROM ${RUST_IMAGE} AS binlex-server-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends libprotobuf-dev protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

ENV PROTOC_INCLUDE=/usr/include

WORKDIR /app

COPY . .

RUN set -eux; \
    cargo build --release -p binlex-server; \
    for manifest in $(find crates/binlex_processors -mindepth 2 -maxdepth 2 -name Cargo.toml | sort); do \
        cargo build --release --manifest-path "$manifest"; \
    done; \
    mkdir -p /tmp/binlex-processors; \
    for path in /app/target/release/binlex-processor-*; do \
        [ -f "$path" ] || continue; \
        [ -x "$path" ] || continue; \
        cp "$path" /tmp/binlex-processors/; \
    done

FROM debian:bookworm-slim AS binlex-server

ARG BINLEX_IMAGE_SOURCE
ARG BINLEX_IMAGE_VERSION
ARG BINLEX_IMAGE_REVISION

LABEL org.opencontainers.image.source="${BINLEX_IMAGE_SOURCE}"
LABEL org.opencontainers.image.version="${BINLEX_IMAGE_VERSION}"
LABEL org.opencontainers.image.revision="${BINLEX_IMAGE_REVISION}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data/binlex-server /opt/binlex/processors /root/.config/binlex /root/.local/share/binlex/processors

WORKDIR /app

COPY --from=binlex-server-builder /app/target/release/binlex-server /usr/local/bin/binlex-server
COPY --from=binlex-server-builder /tmp/binlex-processors/ /opt/binlex/processors/
COPY --from=binlex-server-builder /tmp/binlex-processors/ /root/.local/share/binlex/processors/

EXPOSE 5000

ENV BINLEX_SERVER_LISTEN=0.0.0.0
ENV BINLEX_SERVER_PORT=5000

CMD ["sh", "-lc", "mkdir -p /root/.local/share/binlex/processors && cp -an /opt/binlex/processors/. /root/.local/share/binlex/processors/ && if [ -n \"${BINLEX_SERVER_CONFIG}\" ]; then exec binlex-server --config \"${BINLEX_SERVER_CONFIG}\" --listen \"${BINLEX_SERVER_LISTEN}\" --port \"${BINLEX_SERVER_PORT}\"; else exec binlex-server --listen \"${BINLEX_SERVER_LISTEN}\" --port \"${BINLEX_SERVER_PORT}\"; fi"]
