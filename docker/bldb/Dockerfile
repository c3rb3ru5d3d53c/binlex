FROM python:3.8

COPY . /opt/binlex/

WORKDIR /opt/binlex/lib/python/libblapi/

RUN ./setup.py install

WORKDIR /opt/binlex/docker/bldb/

RUN ./setup.py install

<<<<<<< HEAD
CMD ["./start.sh"]
=======
CMD ["./start.sh"]
>>>>>>> blserver
