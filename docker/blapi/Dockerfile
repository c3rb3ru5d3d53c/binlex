FROM python:3.8

ENV LC_ALL=C
ENV DEBIAN_FRONTEND=noninteractive

COPY . $HOME/binlex/

WORKDIR $HOME/binlex/

RUN apt-get -qq -y update && \
    apt-get install -qq -y build-essential make cmake git

RUN pip install -v .

WORKDIR $HOME/binlex/docker/blapi/

RUN ./setup.py install

CMD touch /var/log/blapi.log && \
    tail -f /var/log/blapi.log