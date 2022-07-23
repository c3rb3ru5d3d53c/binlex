#!/usr/bin/env python

import json
import base64
import logging
import hashlib
from flask import Blueprint
from flask import current_app as app
from flask import request, make_response, send_file
from flask_restx import Namespace, Resource, fields
from pprint import pprint
from bson import json_util
from bson.json_util import loads, dumps
from bson.raw_bson import RawBSONDocument
from bson.objectid import ObjectId
import bsonjs
from libblapiserver.auth import require_user, require_admin
import io

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
            data = request.data
            if io.BytesIO(data).getbuffer().nbytes == 0:
                return {
                    'error': 'File was empty'
                }, 401
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
        except Exception as e:
            return {
                'error': f'Failed to add to decompiler queue: {e}'
            }, 500

#Download sample
@api.route(api_prefix + '/samples/<string:sha256>')
class binlex_samples_download(Resource):
    @require_user
    def get(self, sha256):
        samplecontents = -1
        error = -1
        try:
            response = app.config['minio'].download(
                bucket_name='goodware',
                object_name=sha256)
            if response not in [None, False]:
                samplecontents = response.data
        except Exception as e:
            error = e
        try:
            response = app.config['minio'].download(
                bucket_name='malware',
                object_name=sha256)
            if response not in [None, False]:
                samplecontents = response.data
        except Exception as e:
            error = e
        try:
            response = app.config['minio'].download(
                bucket_name='default',
                object_name=sha256)
            if response not in [None, False]:
                samplecontents = response.data
        except Exception as e:
            error = e
        try:
            response = app.config['minio'].download(
                bucket_name='bldecomp',
                object_name=sha256)
            if response not in [None, False]:
                samplecontents = response.data
        except Exception as e: 
            error = e

        if samplecontents != -1:
            response = send_file(
                io.BytesIO(samplecontents),
                'application/octet-stream'
            )
            return response
        if error != -1:
            return {
                'error': 'download failed'
            }
        return {
            'status': 'could not find requested file to download'
        }
