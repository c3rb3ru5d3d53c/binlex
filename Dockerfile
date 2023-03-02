FROM python:3.8

ENV HOST "0.0.0.0"
ENV PORT "8080"
ENV THREADS "1"
ENV LOG_LEVEL "info"
ENV WORKER_CONNECTIONS "1000"
ENV TIMEOUT "0"

COPY . /opt/binlex/

WORKDIR /opt/binlex/

RUN apt-get -qq -y update && \
    apt-get install -qq -y build-essential make cmake git

RUN pip install -v .

CMD ["sh", "-c", "gunicorn -b ${HOST}:${PORT} --timeout ${TIMEOUT} --threads ${THREADS} --worker-connections ${WORKER_CONNECTIONS} --log-level ${LOG_LEVEL} 'libpybinlex.server:app'"]
