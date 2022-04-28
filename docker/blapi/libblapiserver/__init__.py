#!/usr/bin/env python

from flask import Flask
from flask import current_app as app
from flask_restx import Api
from .apis.binlex import api as api_binlex
from .apis.mongodb import api as api_mongodb
from pprint import pprint

def init_app():
    app = Flask(__name__)
    with app.app_context():
        api = Api(
            app,
            version='1.1.1',
            title='Binlex HTTP API',
            description='Binlex Genetic Binary Lexer HTTP API'
        )
        api.add_namespace(api_binlex)
        api.add_namespace(api_mongodb)
        return app 