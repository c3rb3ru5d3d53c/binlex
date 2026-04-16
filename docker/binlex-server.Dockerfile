FROM ubuntu:24.04 AS builder

RUN set -eux; \
    for attempt in 1 2 3; do \
        rm -rf /var/lib/apt/lists/*; \
        apt-get -o Acquire::Retries=5 update && apt-get install -y --no-install-recommends build-essential ca-certificates curl gnupg libprotobuf-dev libssl-dev lsb-release pkg-config protobuf-compiler software-properties-common && break; \
        if [ "$attempt" -eq 3 ]; then exit 1; fi; \
        sleep 15; \
    done \
    && install -d /usr/share/keyrings \
    && curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors https://apt.llvm.org/llvm-snapshot.gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg \
    && . /etc/os-release \
    && echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] https://apt.llvm.org/${VERSION_CODENAME}/ llvm-toolchain-${VERSION_CODENAME}-22 main" \
        > /etc/apt/sources.list.d/llvm.list \
    && for attempt in 1 2 3; do rm -rf /var/lib/apt/lists/*; apt-get -o Acquire::Retries=5 update && apt-get install -y --no-install-recommends llvm-22-dev clang-22 libclang-common-22-dev libpolly-22-dev && break; if [ "$attempt" -eq 3 ]; then exit 1; fi; sleep 15; done \
    && rm -rf /var/lib/apt/lists/*

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain 1.94.0

ENV LLVM_SYS_221_PREFIX=/usr/lib/llvm-22
ENV PATH=/usr/lib/llvm-22/bin:/root/.cargo/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
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

FROM ubuntu:24.04

ARG BINLEX_IMAGE_SOURCE=https://github.com/c3rb3ru5d3d53c/binlex
ARG BINLEX_IMAGE_VERSION=dev
ARG BINLEX_IMAGE_REVISION=unknown

LABEL org.opencontainers.image.source="${BINLEX_IMAGE_SOURCE}"
LABEL org.opencontainers.image.version="${BINLEX_IMAGE_VERSION}"
LABEL org.opencontainers.image.revision="${BINLEX_IMAGE_REVISION}"

RUN set -eux; \
    for attempt in 1 2 3; do \
        rm -rf /var/lib/apt/lists/*; \
        apt-get -o Acquire::Retries=5 update && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 libstdc++6 && break; \
        if [ "$attempt" -eq 3 ]; then exit 1; fi; \
        sleep 15; \
    done \
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
