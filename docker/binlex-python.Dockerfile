ARG PYTHON_BUILD_IMAGE=python:3.12.13-bookworm
ARG PYTHON_RUNTIME_IMAGE=python:3.12.13-slim-bookworm

FROM ${PYTHON_BUILD_IMAGE} AS builder

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

CMD ["python3"]

RUN pip install --no-cache-dir --upgrade pip maturin[patchelf]

COPY . .

RUN mkdir -p /tmp/binlex-wheels \
    && maturin build --manifest-path bindings/python/Cargo.toml --release --out /tmp/binlex-wheels

FROM ${PYTHON_RUNTIME_IMAGE}

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
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /tmp/binlex-wheels /tmp/binlex-wheels

RUN pip install --no-cache-dir /tmp/binlex-wheels/binlex-*.whl \
    && rm -rf /tmp/binlex-wheels

WORKDIR /app
