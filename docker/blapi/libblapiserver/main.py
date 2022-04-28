#!/usr/bin/env python

import os
import sys
import json
import logging
import configparser
from flask import Flask
from flask_restx import Api
from libblapiserver.apis.binlex import api as api_binlex
from libblapiserver.apis.mongodb import api as api_mongodb
from libblapi.minio import MinIOHandler
from libblapi.mongodb import MongoDBHandler
from libblapi.amqp import AMQPHandler

__version__ = '1.1.1'
__author__ = '@c3rb3ru5d3d53c'

logger = logging.getLogger(__name__)

def create_app(config_file):
    title = "Binlex HTTP API"
    description = "A Binlex HTTP API Server"
    app = Flask(__name__)
    config = configparser.ConfigParser()
    config.read(config_file)

    user_keys = open(config['blapi'].get('user_keys'), 'r').read().splitlines()
    admin_keys = open(config['blapi'].get('admin_keys'), 'r').read().splitlines()

    app.config['config'] = config['blapi'].get('host')
    app.config['version'] = __version__
    app.config['debug'] = config['blapi'].getboolean('debug')
    app.config['port'] = config['blapi'].getint('port')
    app.config['amqp_queue_traits'] = config['amqp'].get('traits_queue')
    app.config['amqp_queue_decomp'] = config['amqp'].get('decomp_queue')
    app.config['user_keys'] = user_keys
    app.config['admin_keys'] = admin_keys
    app.config['mongodb'] = MongoDBHandler(config)
    app.config['amqp'] = AMQPHandler(config)
    app.config['minio'] = MinIOHandler(config)

    with app.app_context():
        @app.errorhandler(404)
        def page_not_found(e):
            return {'error': 'not found'}, 404
        api = Api(
            app,
            version=__version__,
            title=title,
            description=description
        )
        api.add_namespace(api_binlex)
        api.add_namespace(api_mongodb)

    return app