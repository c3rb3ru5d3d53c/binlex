FROM python:3.8

ENV LC_ALL=C
ENV DEBIAN_FRONTEND=noninteractive

COPY . $HOME/binlex/

WORKDIR $HOME/binlex/

RUN apt -qq -y update && \
    apt install -qq -y build-essential make cmake git

RUN make threads=4 args="-DBUILD_PYTHON_BINDINGS=true -DPYBIND11_PYTHON_VERSION=3.8"

RUN make install

WORKDIR $HOME/binlex/docker/blapi/

RUN ./setup.py install

CMD touch /var/log/blapi.log && \
    tail -f /var/log/blapi.log