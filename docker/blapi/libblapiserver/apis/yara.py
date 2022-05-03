#!/usr/bin/env python

import yara
from hashlib import sha256
from flask import Blueprint
from flask import current_app as app
from flask import request
from flask_restx import Namespace, Resource, fields

api = Namespace('yara', description='Binlex YARA API')

@api.route('/version')
class binlex_methods(Resource):
    def get(self):
        return {
            'version': yara.__version__
        }

@api.route('/scan')
class binlex_pe(Resource):
    def post(self):
        """Scan File"""
        return 'Placeholder'
