
FROM python:3.8

COPY . /opt/binlex/

WORKDIR /opt/binlex/

RUN apt-get -qq -y update && \
    apt-get install -qq -y build-essential make cmake git

RUN pip install -v .

WORKDIR /opt/binlex/lib/python/libblapi/

RUN ./setup.py install

WORKDIR /opt/binlex/docker/bldec/

RUN ./setup.py install

CMD ["./start.sh"]