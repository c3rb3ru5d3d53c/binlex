FROM rust:1.94-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends libprotobuf-dev protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

ENV PROTOC_INCLUDE=/usr/include

WORKDIR /app

COPY . .

RUN set -eux; \
    cargo build --release -p binlex-web

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
    && mkdir -p /data/binlex-web /root/.config/binlex /root/.local/share/binlex/index

WORKDIR /app

COPY --from=builder /app/target/release/binlex-web /usr/local/bin/binlex-web

EXPOSE 8000

ENV BINLEX_WEB_LISTEN=0.0.0.0
ENV BINLEX_WEB_PORT=8000
ENV BINLEX_WEB_URL=http://127.0.0.1:8000
ENV BINLEX_WEB_CONFIG=/root/.config/binlex/binlex-web.toml
ENV BINLEX_WEB_SERVER_URL=http://binlex-server:5000
ENV BINLEX_WEB_CORPUS=default

CMD ["sh", "-lc", "mkdir -p /data/binlex-web /root/.config/binlex /root/.local/share/binlex/index && if [ ! -f \"${BINLEX_WEB_CONFIG}\" ]; then cat > \"${BINLEX_WEB_CONFIG}\" <<EOF\n[binlex.web]\nlisten = \"${BINLEX_WEB_LISTEN}\"\nport = ${BINLEX_WEB_PORT}\nurl = \"${BINLEX_WEB_URL}\"\ncorpus = \"${BINLEX_WEB_CORPUS}\"\n\n[binlex.web.server]\nurl = \"${BINLEX_WEB_SERVER_URL}\"\n\n[binlex.web.index.local]\nenabled = true\npath = \"/root/.local/share/binlex/index\"\nEOF\nfi && exec binlex-web --listen \"${BINLEX_WEB_LISTEN}\" --port \"${BINLEX_WEB_PORT}\" --url \"${BINLEX_WEB_URL}\""]
