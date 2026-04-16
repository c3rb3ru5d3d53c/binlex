ARG UBUNTU_IMAGE=ubuntu:24.04

FROM ${UBUNTU_IMAGE} AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        gnupg \
        libprotobuf-dev \
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

CMD ["python3"]

RUN python3 -m pip install --break-system-packages --no-cache-dir maturin[patchelf]

COPY . .

RUN mkdir -p /tmp/binlex-wheels \
    && python3 -m maturin build --manifest-path bindings/python/Cargo.toml --release --out /tmp/binlex-wheels

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
        libstdc++6 \
        python3 \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /tmp/binlex-wheels /tmp/binlex-wheels

RUN python3 -m venv /opt/binlex-venv \
    && /opt/binlex-venv/bin/pip install --no-cache-dir /tmp/binlex-wheels/binlex-*.whl \
    && rm -rf /tmp/binlex-wheels

WORKDIR /app

ENV PATH=/opt/binlex-venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
