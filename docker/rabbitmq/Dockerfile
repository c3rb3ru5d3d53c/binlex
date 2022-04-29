FROM rabbitmq:3.9-management

ARG UID=1000
ARG GID=1000

RUN usermod -u $UID rabbitmq
RUN groupmod -g $GID rabbitmq

EXPOSE 15691 15692 25672

CMD ["rabbitmq-server"]
