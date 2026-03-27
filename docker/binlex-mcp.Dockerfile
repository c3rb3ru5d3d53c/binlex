ARG BINLEX_PYTHON_IMAGE=binlex-python:latest

FROM rust:1.94-bookworm AS builder

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

FROM ${BINLEX_PYTHON_IMAGE}

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
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data/binlex-mcp /opt/binlex/processors /root/.config/binlex /root/.local/share/binlex/processors /samples

RUN pip install --no-cache-dir \
        requests==2.33.0 \
        yara-python==4.5.4 \
        python-magic==0.4.27

WORKDIR /app

COPY --from=builder /app/target/release/binlex-mcp /usr/local/bin/binlex-mcp
COPY --from=builder /tmp/binlex-processors/ /opt/binlex/processors/
COPY --from=builder /tmp/binlex-processors/ /root/.local/share/binlex/processors/
COPY --from=builder /app/crates/binlex_tools/binlex-mcp/skills /opt/binlex-mcp/skills

ENV BINLEX_MCP_LISTEN=0.0.0.0
ENV BINLEX_MCP_PORT=3000
ENV BINLEX_MCP_BASE_URL=
ENV BINLEX_MCP_CONFIG=/root/.config/binlex/binlex-mcp.toml
ENV BINLEX_MCP_SAMPLES=/root/.local/share/binlex/samples

EXPOSE 3000

CMD ["sh", "-lc", "mkdir -p /data/binlex-mcp /root/.config/binlex /root/.local/share/binlex/processors \"${BINLEX_MCP_SAMPLES}\" && cp -an /opt/binlex/processors/. /root/.local/share/binlex/processors/ && if [ ! -f \"${BINLEX_MCP_CONFIG}\" ]; then init_source=\"${BINLEX_MCP_INIT_SOURCES:-/opt/binlex-mcp/skills}\"; binlex-mcp init --yes --config \"${BINLEX_MCP_CONFIG}\" \"${init_source}\"; fi && exec binlex-mcp serve --config \"${BINLEX_MCP_CONFIG}\" --samples \"${BINLEX_MCP_SAMPLES}\" --listen \"${BINLEX_MCP_LISTEN}\" --port \"${BINLEX_MCP_PORT}\""]
