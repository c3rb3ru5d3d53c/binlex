FROM pybinlex:1.1.1

COPY . /opt/binlex/

WORKDIR /opt/binlex/lib/python/libblapi/

RUN ./setup.py install

WORKDIR /opt/binlex/docker/bldec/

RUN ./setup.py install

CMD ["./start.sh"]
