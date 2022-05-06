FROM python:3.8

ENV LC_ALL=C
ENV DEBIAN_FRONTEND=noninteractive

COPY . /opt/binlex/

WORKDIR /opt/binlex/

RUN apt-get -qq -y update && \
    apt-get install -qq -y build-essential make cmake git wget nano curl nginx net-tools

RUN pip install gunicorn

WORKDIR /opt/binlex/lib/python/libblapi/

RUN ./setup.py install

WORKDIR /opt/binlex/docker/blapi/

RUN ./setup.py install

CMD ["sh", "start.sh"]
