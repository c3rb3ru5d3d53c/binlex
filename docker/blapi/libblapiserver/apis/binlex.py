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

__version__ = '1.1.1'

__pybinversion__ = '2.2.2'

logger = logging.getLogger(__name__)

api = Namespace('binlex', description='Binlex Upload API')

methods = ['store', 'lex']

pe_architectures = ['x86', 'x86_64']

elf_architectures = ['x86', 'x86_64']

raw_architectures = ['x86', 'x86_64']

corpra = ['default', 'malware', 'goodware']

def jsonify(data):
    return json.loads(json.dumps(data, default=json_util.default))

@api.route('/version')
class binlex_version(Resource):
    @require_user
    def get(self):
        """Get the Current Version of Binlex"""
        return {
            'version': __version__
        }

@api.route('/methods')
class binlex_methods(Resource):
    @require_user
    def get(self):
        """Get the List of Supported Methods"""
        return methods

@api.route('/pe/architectures')
class binlex_pe_architectures(Resource):
    @require_user
    def get(self):
        """Get the List of Supported PE Format Architectures"""
        return pe_architectures

@api.route('/elf/architectures')
class binlex_elf_architectures(Resource):
    @require_user
    def get(self):
        """Get the List of Supported ELF Format Architectures"""
        return elf_architectures

@api.route('/raw/architectures')
class binlex_raw_architectures(Resource):
    @require_user
    def get(self):
        """Get the List of Supported RAW Format Architectures"""
        return raw_architectures

@api.route('/corpra')
class binlex_corpra(Resource):
    @require_user
    def get(self):
        return corpra

@api.route('/decompile/<string:mode>/<string:corpus>')
class binlex_decompile(Resource):
    @require_user
    def post(self, mode, corpus):
        try:
            if corpus not in corpra:
                return {
                    'error': 'invalid corpus value'
                }, 401
            app.config['minio'].upload(
                bucket_name=app.config['amqp_queue_decomp'],
                data=request.data)
            app.config['amqp'].publish(
                queue=app.config['amqp_queue_decomp'],
                body=json.dumps({
                    'corpus': corpus,
                    'mode': mode,
                    'object_name': hashlib.sha256(request.data).hexdigest()
                }))
            return {
                'status': 'processing'
            }
        except Exception:
            return {
                'error': 'failed to add to decompiler queue'
            }, 500

@api.route('/decompile/status/<string:sha256>')
class binlex_decompile_status(Resource):
    @require_user
    def get(self, sha256):
        try:
            data = app.config['minio'].download(
                bucket_name=app.config['amqp_queue_decomp'],
                object_name=sha256)
            if data in [None, False]:
                return {
                    'status': 'completed'
                }
            return {
                'status': 'processing'
            }
        except Exception:
            return {
                'status': 'completed'
            }

#Download sample
@api.route('/api/v1/samples/<str:sha256>')
class binlex_v1_samples_download(Resource):
    @require_user
    def get(self, sha256):
        try:
            data = app.config['minio'].download
                bucket_name=app.config['amqp_queue_decomp'],
                object_name=sha256)
            if data in [None, False]:
                return {
                    print "error: no data"
                }
            return {
                print "return object"
            }
        except Exception:
            return {
                print "return exception?"
            }

#Upload sample to sample queue
@api.route('/api/v1/samples/<str:sha256>/<str:mode>')
class binlex_v1_samples_upload(Resource):
    @require_user
    def get(self, sha256):
        try:

#Get version of pybinlex
@api.route('/api/v1/version')
class binlex_v1_version(Resource):
    @require_user
    def get(self):
        """Get the Current Version of Binlex"""
        return {
            'version 1': __pybinversion__
        }

#Check if sample exists
@api.route('/api/v1/samples/<str:corpus>/<str:sha256>')
class binlex_v1_samples(Resource):
    @require_user
    def head(self, corpus, sha256):
        try:
            data = app.config['minio'].download(
                bucket_name=app.config['amqp_queue_decomp'],
                object_name=sha256)
            if data in [None, False]:
                return {
                    'exists': 'false'
                }
            return {
                'exists': 'true'
            }
        except Exception:
            return {
                'status': 'completed'
            }

#Body contains raw mongodb query
@api.route('/api/v1/traits')
class binlex_v1_traits(Resource):
    @require_user
    def post(self)
        try:
            #if body does not contain mongodb
            #body=json.dumps(
                return{
                    'mongodb': 'does not exist'
                }

