#!/usr/bin/env bash

# Main Loop
while true; do
    rm -f /var/run/blapi.pid # this removes pid file from previous gunicorn start
    /etc/init.d/nginx start
    echo "[-] starting gunicorn..."
    gunicorn -D -p /var/run/blapi.pid -b 127.0.0.1:5000 "libblapiserver.main:create_app('/startup/blapi.conf')" --error-logfile /var/log/blapi.log
    if [ -f /var/run/blapi.pid ]; then
        echo "[*] pid exists, watching logs"
        tail -f /var/log/nginx/access.log /var/log/nginx/error.log /var/log/blapi.log
    else
        echo "[x] failed to start blapi, restarting..."
        tail -8 /var/log/blapi.log
    fi
    sleep 10;
done
