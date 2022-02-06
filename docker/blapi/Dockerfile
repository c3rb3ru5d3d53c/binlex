FROM ubuntu:20.04

ENV LC_ALL=C
ENV DEBIAN_FRONTEND=noninteractive

COPY . /opt/binlex/

WORKDIR /opt/binlex/

RUN apt-get -qq -y update && \
    apt-get install -qq -y build-essential make cmake git uwsgi uwsgi uwsgi-plugin-python3 python3 python3-pip wget nano curl nginx net-tools

WORKDIR /opt/binlex/lib/python/libblapi/

RUN python3 setup.py install

WORKDIR /opt/binlex/docker/blapi/

RUN python3 setup.py install

CMD touch /var/log/blapi.log && tail -f /var/log/blapi.log

#CMD uwsgi -d --plugin /usr/lib/uwsgi/plugins/python3_plugin.so --ini /config/blapi_uwsgi.ini && /etc/init.d/nginx start && tail -f /var/log/nginx/access.log /var/log/nginx/error.log

#CMD ["./start.sh"]
