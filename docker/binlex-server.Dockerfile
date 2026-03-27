FROM rust:1.94-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends libprotobuf-dev protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

ENV PROTOC_INCLUDE=/usr/include

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release \
    --bin binlex-server \
    --bin binlex-processor-vex \
    --bin binlex-processor-embeddings

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data/binlex-server /root/.config/binlex

WORKDIR /app

COPY --from=builder /app/target/release/binlex-server /usr/local/bin/binlex-server
COPY --from=builder /app/target/release/binlex-processor-vex /usr/local/bin/binlex-processor-vex
COPY --from=builder /app/target/release/binlex-processor-embeddings /usr/local/bin/binlex-processor-embeddings

EXPOSE 5000

CMD ["sh", "-lc", "if [ -n \"${BINLEX_SERVER_CONFIG}\" ]; then exec binlex-server --config \"${BINLEX_SERVER_CONFIG}\"; else exec binlex-server; fi"]
