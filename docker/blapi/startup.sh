#!/usr/bin/env bash

while true; do
    uwsgi --ini /config/blapi_uwsgi.ini
    sleep 10;
done