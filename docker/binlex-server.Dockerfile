FROM rust:1.94-bookworm AS builder

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

FROM debian:bookworm-slim

ARG BINLEX_IMAGE_SOURCE=https://github.com/c3rb3ru5d3d53c/binlex
ARG BINLEX_IMAGE_VERSION=dev
ARG BINLEX_IMAGE_REVISION=unknown

LABEL org.opencontainers.image.source="${BINLEX_IMAGE_SOURCE}"
LABEL org.opencontainers.image.version="${BINLEX_IMAGE_VERSION}"
LABEL org.opencontainers.image.revision="${BINLEX_IMAGE_REVISION}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data/binlex-server /opt/binlex/processors /root/.config/binlex /root/.local/share/binlex/processors

WORKDIR /app

COPY --from=builder /app/target/release/binlex-server /usr/local/bin/binlex-server
COPY --from=builder /tmp/binlex-processors/ /opt/binlex/processors/
COPY --from=builder /tmp/binlex-processors/ /root/.local/share/binlex/processors/

EXPOSE 5000

ENV BINLEX_SERVER_LISTEN=0.0.0.0
ENV BINLEX_SERVER_PORT=5000
ENV BINLEX_SERVER_PROCESSORS=
ENV BINLEX_SERVER_PROCESSES=
ENV BINLEX_SERVER_PROCESSOR_DIRECTORY=

CMD ["sh", "-lc", "mkdir -p /root/.local/share/binlex/processors && cp -an /opt/binlex/processors/. /root/.local/share/binlex/processors/ && set -- binlex-server --listen \"${BINLEX_SERVER_LISTEN}\" --port \"${BINLEX_SERVER_PORT}\"; if [ -n \"${BINLEX_SERVER_CONFIG}\" ]; then set -- \"$@\" --config \"${BINLEX_SERVER_CONFIG}\"; fi; if [ -n \"${BINLEX_SERVER_PROCESSORS}\" ]; then set -- \"$@\" --processors \"${BINLEX_SERVER_PROCESSORS}\"; fi; if [ -n \"${BINLEX_SERVER_PROCESSES}\" ]; then set -- \"$@\" --processes \"${BINLEX_SERVER_PROCESSES}\"; fi; if [ -n \"${BINLEX_SERVER_PROCESSOR_DIRECTORY}\" ]; then set -- \"$@\" --processor-directory \"${BINLEX_SERVER_PROCESSOR_DIRECTORY}\"; fi; exec \"$@\""]
