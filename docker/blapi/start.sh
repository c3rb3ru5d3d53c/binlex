#!/usr/bin/env bash

while true; do
    uwsgi --plugin /usr/lib/uwsgi/plugins/python3_plugin.so --ini /config/blapi_uwsgi.ini
    sleep 10;
done