#!/usr/bin/env python

import pika
import ssl


class AMQPHandler:
    """
    AMQP Handler
    """

    def __init__(self, config):
        self.amqp = None
        self.consumer_channel = None
        self.publisher_channel = None

        username = config['amqp'].get('user')
        password = config['amqp'].get('pass')
        port = config['amqp'].getint('port')

        num_hosts = int(config['amqp'].get('hosts'))
        self.all_hosts = []

        tls = config['amqp'].getboolean('tls')

        if tls:
            context = ssl.create_default_context(cafile=config['amqp'].get('ca'))
            context.load_cert_chain(config['amqp'].get('cert'), config['amqp'].get('key'))
            ssl_options = pika.SSLOptions(context, config['amqp'].get('host'))

        for num in range(1, num_hosts):
            conn_params = pika.ConnectionParameters(port=port,
                                                    host="rabbitmq-broker" + str(num),
                                                    ssl_options=(ssl_options if tls else None),
                                                    credentials=pika.credentials.PlainCredentials(
                                                        username=username, password=password),
                                                    heartbeat=600, blocked_connection_timeout=300)
            self.all_hosts.append(conn_params)

        self.establish_connection()

    def establish_connection(self):
        self.amqp = pika.BlockingConnection(self.all_hosts)

        self.publisher_channel = self.amqp.channel()
        self.consumer_channel = self.amqp.channel()

    def publish(self, queue, body):
        self.publisher_channel.queue_declare(queue=queue)
        self.publisher_channel.basic_publish(exchange='', routing_key=queue, body=body)

    def consume(self, queue, callback):
        while True:
            try:
                self.consumer_channel.queue_declare(queue=queue)
                self.consumer_channel.basic_consume(queue=queue, on_message_callback=callback)
                self.consumer_channel.start_consuming()
            except pika.exceptions.AMQPConnectionError:
                print("Connection was closed, retrying...")
                self.establish_connection()
                continue
