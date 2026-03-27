FROM rust:1.94-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libprotobuf-dev \
        protobuf-compiler \
        python3 \
        python3-venv \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

ENV PROTOC_INCLUDE=/usr/include

WORKDIR /app

ENV VIRTUAL_ENV=/opt/binlex-venv
ENV PATH=/opt/binlex-venv/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

COPY . .

RUN cargo build --release -p binlex-mcp --bin binlex-mcp

RUN python3 -m venv /opt/binlex-venv \
    && pip install --no-cache-dir --upgrade pip maturin[patchelf] \
    && mkdir -p /tmp/binlex-wheels \
    && maturin build --manifest-path bindings/python/Cargo.toml --release --out /tmp/binlex-wheels \
    && pip install --no-cache-dir /tmp/binlex-wheels/binlex-*.whl \
        requests==2.33.0 \
        yara-python==4.5.4 \
        python-magic==0.4.27

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libgcc-s1 \
        libstdc++6 \
        python3 \
        python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data/binlex-mcp /root/.config/binlex /samples

WORKDIR /app

COPY --from=builder /app/target/release/binlex-mcp /usr/local/bin/binlex-mcp
COPY --from=builder /opt/binlex-venv /opt/binlex-venv
COPY --from=builder /app/crates/binlex_tools/binlex-mcp/skills /opt/binlex-mcp/skills

ENV VIRTUAL_ENV=/opt/binlex-venv
ENV PATH=/opt/binlex-venv/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV BINLEX_MCP_LISTEN=0.0.0.0
ENV BINLEX_MCP_PORT=5001
ENV BINLEX_MCP_CONFIG=/root/.config/binlex/binlex-mcp.toml
ENV BINLEX_MCP_SAMPLES=/data/binlex-mcp/samples

EXPOSE 5001

CMD ["sh", "-lc", "mkdir -p /data/binlex-mcp /root/.config/binlex \"${BINLEX_MCP_SAMPLES}\" && if [ ! -f \"${BINLEX_MCP_CONFIG}\" ]; then init_source=\"${BINLEX_MCP_INIT_SOURCES:-/opt/binlex-mcp/skills}\"; binlex-mcp init --yes --config \"${BINLEX_MCP_CONFIG}\" \"${init_source}\"; fi && exec binlex-mcp serve --config \"${BINLEX_MCP_CONFIG}\" --samples \"${BINLEX_MCP_SAMPLES}\" --listen \"${BINLEX_MCP_LISTEN}\" --port \"${BINLEX_MCP_PORT}\""]
