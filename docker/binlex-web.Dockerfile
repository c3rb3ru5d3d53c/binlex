FROM ubuntu:24.04 AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg libprotobuf-dev lsb-release protobuf-compiler software-properties-common wget \
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
    cargo build --release -p binlex-web

FROM ubuntu:24.04

ARG BINLEX_IMAGE_SOURCE=https://github.com/c3rb3ru5d3d53c/binlex
ARG BINLEX_IMAGE_VERSION=dev
ARG BINLEX_IMAGE_REVISION=unknown

LABEL org.opencontainers.image.source="${BINLEX_IMAGE_SOURCE}"
LABEL org.opencontainers.image.version="${BINLEX_IMAGE_VERSION}"
LABEL org.opencontainers.image.revision="${BINLEX_IMAGE_REVISION}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 libstdc++6 linux-tools-generic procps \
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
ENV BINLEX_WEB_LOCK_CORPORA=
ENV BINLEX_WEB_IDLE=

CMD ["sh", "-lc", "mkdir -p /data/binlex-web /root/.config/binlex /root/.local/share/binlex/index && if [ ! -f \"${BINLEX_WEB_CONFIG}\" ]; then cat > \"${BINLEX_WEB_CONFIG}\" <<EOF\n[binlex-web]\nlisten = \"${BINLEX_WEB_LISTEN}\"\nport = ${BINLEX_WEB_PORT}\nurl = \"${BINLEX_WEB_URL}\"\ncorpus = \"${BINLEX_WEB_CORPUS}\"\n\n[binlex-web.binlex-server]\nurl = \"${BINLEX_WEB_SERVER_URL}\"\n\n[binlex-web.index.local]\nenabled = true\npath = \"/root/.local/share/binlex/index\"\n\n[binlex-web.upload.sample.corpora]\nlock = false\ndefault = [\"default\", \"goodware\", \"malware\"]\nEOF\nfi && if [ -n \"${BINLEX_WEB_IDLE}\" ]; then echo \"binlex-web idle profiling mode enabled\"; while true; do sleep 3600; done; fi && lock_corpora_arg=\"\" && if [ -n \"${BINLEX_WEB_LOCK_CORPORA}\" ]; then lock_corpora_arg=\"--lock-corpora\"; fi && exec binlex-web --listen \"${BINLEX_WEB_LISTEN}\" --port \"${BINLEX_WEB_PORT}\" --url \"${BINLEX_WEB_URL}\" --server \"${BINLEX_WEB_SERVER_URL}\" ${lock_corpora_arg}"]
