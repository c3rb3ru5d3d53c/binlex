FROM mongo:5.0.5

ARG UID=1000
ARG GID=1000

RUN usermod -u $UID mongodb
RUN groupmod -g $GID mongodb

EXPOSE 27017

CMD ["mongod"]