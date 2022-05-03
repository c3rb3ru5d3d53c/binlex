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

__pybinversion__ = '2.2.2'

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
@api.route(api_prefix + '/samples/<string:sha256>')
class binlex_samples_download(Resource):
    @require_user
    def get(self, sha256):
        try:
            data = app.config['minio'].download(
                bucket_name='goodware',
                object_name=sha256)
            if data in [None, False]:
                return {
                    'error': 'no matching sample to download'
                }
            if data in [True]:
                jsondata = data.json()
                return data
                return {
                    'return': 'sample has been downloaded'
                }
        except:
            pass
        try:
            data = app.config['minio'].download(
                bucket_name='malware',
                object_name=sha256)
            if data in [None, False]:
                return {
                    'error': 'no matching sample to download'
                }
            if data in [True]:
                jsondata = data.json()
                return data
                return {
                    'return': 'sample has been downloaded'
                }
        except:
            pass
        try:
            data = app.config['minio'].download(
                bucket_name='default',
                object_name=sha256)
            if data in [None, False]:
                return {
                    'error': 'no matching sample to download'
                }
            if data in [True]:
                jsondata = data.json()
                return data
                return {
                    'return': 'sample has been downloaded'
                }
        except:
            pass
        try:
            data = app.config['minio'].download(
                bucket_name='bldecomp',
                object_name=sha256)
            if data in [None, False]:
                return {
                    'error': 'no matching sample to download'
                }
            if data in [True]:
                jsondata = data.json()
                return data
                return {
                    'return': 'sample has been downloaded'
                }
        except Exception:
            return {
                'status': 'download failed'
            }
        return {
            'status': 'could not find requested file to download'
        }
"""
#Upload sample to sample queue
@api.route('/api/v1/samples/<str:sha256>/<string:mode>')
class binlex_v1_samples_upload(Resource):
    @require_user
    def get(self, sha256):
        try:

#Check if sample exists
@api.route(api_prefix + 'samples/<str:corpus>/<string:sha256>')
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
@api.route(api_prefix + '/traits')
class binlex_v1_traits(Resource):
    @require_user
    def post(self)
        try:
            #if body does not contain mongodb
            if body=json.dump != true:
                return{
                    'mongodb': 'does not exist'
                }
            return {
                'mongodb': 'exists'
            }
            
#List of sha256 samples with the same trait
@api.route(api_prefix + '/traits/<string:corpus>/<string:sha256>')
class binlex_sha256_same_traits(Resource):
    @require_user
    def get(self, corpus, sha256)
        return traits
        for that trait hash 
        for any traits for the sha256 hash
        found in the file schema.js
        with the corpus of the one we are looking at.
        That trait is found in all of these files.

#List of sha256 samples with similar traits
@api.route(api_prefix + '/traits/<string:corpus>/<string:tlsh>/<<int:distance>')
class binlex_sha256_similar_traits(Resource):
    @require_user
    def get(self, corpus, tlsh, distance)
        return traits

#List of similar thraits
@api.route(api_prefix + '/traits/<string:corpus>/<string:tlsh>/<<int:distance>')
class binlex_similar_traits(Resource):
    @require_user
    def get(self, corpus, tlsh, distance)
        return traits
        
#Searching hexadecimal string by hand (de ad be ef), w/ wildcards
@api.route(api_prefix + '/traits/<string:hexstr>')
class binlex_traits_searching_hex_string(Resource):
    @require_user
    def get(self, hexstr)
        return traits

#create tags a sha256 trait in a specific corpus
@api.route(api_prefix + '/traits/<string:corpus>/<string:sha256>')
class binlex_traits_searching_hex_string(Resource):
    @require_user
    def post(self, corpus, sha256)
        return traits

#create tags sha256 of the sample in the object store
@api.route(api_prefix + '/samples/<string:corpus>/<string:sha256>')
class binlex_traits_searching_hex_string(Resource):
    @require_user
    def post(self, corpus, sha256)
        return traits

#delete tag a sha256 trait in a specific corpus
@api.route(api_prefix + '/traits/<string:corpus>/<string:sha256>')
class binlex_traits_searching_hex_string(Resource):
    @require_user
    def delete(self, corpus, sha256)
        return traits

#delete tags sha256 of the sample in the object store
@api.route(api_prefix + '/samples/<string:corpus>/<string:sha256>')
class binlex_samples_delete_hex_string(Resource):
    @require_user
    def delete(self, corpus, sha256)
        return traits

"""