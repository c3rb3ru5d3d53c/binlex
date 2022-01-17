from python:3.8

ADD ./* $HOME/blworker/

WORKDIR $HOME/blworker/

RUN ./setup.py install

CMD touch /var/log/blworker.log && \
    tail -f /var/log/blworker.log
