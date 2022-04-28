#!/usr/bin/env bash

while true; do
    gunicorn -D -b 127.0.0.1:5000 "libblapiserver.main:create_app('/startup/blapi.conf')" && \
        /etc/init.d/nginx start && \
        tail -f /var/log/nginx/access.log /var/log/nginx/error.log;
    sleep 10;
done