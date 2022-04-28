#!/usr/bin/env python

import pika
import ssl

class AMQPHandler():

    """
    AMQP Handler
    """

    def __init__(self, config):
        if config['amqp'].getboolean('tls') is True:
            context = ssl.create_default_context(
                cafile=config['amqp'].get('ca'))
            context.load_cert_chain(config['amqp'].get('cert'), config['amqp'].get('key'))
            ssl_options = pika.SSLOptions(context, config['amqp'].get('host'))
            conn_params = pika.ConnectionParameters(port=config['amqp'].getint('port'),
                                                    host=config['amqp'].get('host'),
                                                    ssl_options=ssl_options,
                                                    credentials=pika.credentials.PlainCredentials(
                                                        username=config['amqp'].get('user'),
                                                        password=config['amqp'].get('pass')))
        else:
            conn_params = pika.ConnectionParameters(port=config['amqp'].getint('port'),
                                                    host=config['amqp'].get('host'),
                                                    credentials=pika.credentials.PlainCredentials(
                                                        username=config['amqp'].get('user'),
                                                        password=config['amqp'].get('pass')))
        self.amqp = pika.BlockingConnection(conn_params)
        self.amqp_channel = self.amqp.channel()

    def publish(self, queue, body):
        amqp_channel = self.amqp.channel()
        amqp_channel.queue_declare(queue=queue)
        amqp_channel.basic_publish(exchange='', routing_key=queue, body=body)

    def consume(self, queue, callback):
        amqp_channel = self.amqp.channel()
        amqp_channel.queue_declare(queue=queue)
        amqp_channel.basic_consume(queue=queue, on_message_callback=callback)
        amqp_channel.start_consuming()