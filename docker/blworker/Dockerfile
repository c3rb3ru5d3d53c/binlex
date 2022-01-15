from node:latest

ADD ./* $HOME/blworker/

WORKDIR $HOME/blworker/

RUN npm install

CMD touch /var/log/blworker.log && \
    tail -f /var/log/blworker.log
