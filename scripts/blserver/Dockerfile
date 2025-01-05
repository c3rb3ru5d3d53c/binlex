FROM pytorch/pytorch:2.5.1-cuda12.4-cudnn9-runtime

WORKDIR /app

COPY . /app

RUN apt-get update && apt-get install -y curl git build-essential pkg-config libssl-dev

RUN pip install --no-cache-dir -r requirements.txt

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y

RUN echo 'source $HOME/.cargo/env' >> $HOME/.bashrc

RUN git clone https://github.com/c3rb3ru5d3d53c/binlex.git && \
    cd binlex/src/bindings/python/ && \
    bash -c 'source /root/.cargo/env; pip install --no-cache-dir maturin[patchelf]; maturin build; pip install --no-cache-dir /app/binlex/target/wheels/*.whl; cargo clean'

RUN cp configs/blserver.toml.bak config.toml

ENV CONFIG=/app/config.toml

ENV PORT=5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:$PORT", "blserver:create_app('$CONFIG')"]
