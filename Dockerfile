FROM python:3.8

COPY . /opt/binlex/

WORKDIR /opt/binlex/

RUN apt-get -qq -y update && \
    apt-get install -qq -y build-essential make cmake git

RUN pip install -v .

CMD ["gunicorn", "-b", "0.0.0.0:8080", "--timeout", "0", "libpybinlex.webapi:create_app()"]
