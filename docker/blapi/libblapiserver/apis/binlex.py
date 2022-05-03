#!/usr/bin/env python

import json
import base64
import logging
import hashlib
from flask import Blueprint
from flask import current_app as app
from flask import request, make_response
from flask_restx import Namespace, Resource, fields
from pprint import pprint
from bson import json_util
from bson.json_util import loads, dumps
from bson.raw_bson import RawBSONDocument
from bson.objectid import ObjectId
import bsonjs
from libblapiserver.auth import require_user, require_admin

api_prefix = "/api/v1"

__pybinlex_version__ = '1.1.1'

logger = logging.getLogger(__name__)

api = Namespace('binlex', description='Binlex Upload API')

corpra = ['default', 'malware', 'goodware']

modes = ['elf:x86', 'elf:x86_64', 'pe:x86', 'pe:x86_64', 'raw:x86', 'raw:x86_64', 'raw:cil', 'pe:cil', 'auto']

def jsonify(data):
    return json.loads(json.dumps(data, default=json_util.default))

@api.route(api_prefix + '/corpra')
class binlex_corpra(Resource):
    @require_user
    def get(self):
        return corpra

@api.route(api_prefix + '/version')
class binlex_version(Resource):
    @require_user
    def get(self):
        return {
            'version': __pybinlex_version__
        }

@api.route(api_prefix + '/modes')
class binlex_modes(Resource):
    @require_user
    def get(self):
        return modes

@api.route(api_prefix + '/samples/<string:corpus>/<string:mode>')
class binlex_samples_upload(Resource):
    @require_user
    def post(self, corpus, mode):
        if corpus not in corpra : 
            return {
                'error': 'Invalid corpus value, mode must be one of the following: ' + ', '.join(corpra)
            }, 401
        if mode not in modes :
            return {
                'error': 'Invalid mode value, mode must be one of the following: ' + ', '.join(modes)
            }, 401

        try:
            f = request.files['filedata']
            data = f.read()
            app.config['minio'].upload(
                bucket_name=corpus,
                data=data
            )

            app.config['amqp'].publish(
                queue=app.config['amqp_queue_decomp'],
                body=json.dumps({
                    'corpus': corpus,
                    'mode': mode,
                    'object_name': hashlib.sha256(data).hexdigest()
                }))
            return {
                'status': 'processing'
            }
        except Exception:
            return {
                'error': 'Failed to add to decompiler queue'
            }, 500