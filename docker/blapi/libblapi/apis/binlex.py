#!/usr/bin/env python

import json
import base64
import logging
import pybinlex
from hashlib import sha256
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
from libblapi.auth import require_user, require_admin

logger = logging.getLogger(__name__)

api = Namespace('binlex', description='Binlex Upload API')

methods = ['store', 'lex']

pe_architectures = ['x86', 'x86_64']

elf_architectures = ['x86', 'x86_64']

raw_architectures = ['x86', 'x86_64']

corpra = ['default', 'malware', 'goodware']

def jsonify(data):
    return json.loads(json.dumps(data, default=json_util.default))

def is_corpus(corpus):
    if corpus in corpra:
        return True
    if corpus.startswith(tuple([value + '.' for value in corpra])):
        return True
    return False

def is_elf_arch(arch):
    if arch in elf_architectures:
        return True
    return False

def is_pe_arch(arch):
    if arch in pe_architectures:
        return True
    return False

def is_raw_arch(arch):
    if arch in raw_architectures:
        return True
    return False

def is_method(method):
    if method in methods:
        return True
    return False

def validate_raw(method, corpus, architecture):
    if is_method(method) is False:
        return {
            'error': method + ' is a valid method, GET /binlex/methods to show valid methods'
        }
    if is_corpus(corpus) is False:
        return {
            'error': corpus + ' is not a valid corpus, GET /binlex/corpra to show valid corpra'
        }
    if is_raw_arch(architecture) is False:
        return {
            'error': architecture + ' is not a valid architecture, GET /binlex/<format>/architectures to show valid architectures'
        }
    return True

def validate_pe(method, corpus, architecture):
    if is_method(method) is False:
        return {
            'error': method + ' is a valid method, GET /binlex/methods to show valid methods'
        }
    if is_corpus(corpus) is False:
        return {
            'error': corpus + ' is not a valid corpus, GET /binlex/corpra to show valid corpra'
        }
    if is_pe_arch(architecture) is False:
        return {
            'error': architecture + ' is not a valid architecture, GET /binlex/<format>/architectures to show valid architectures'
        }
    return True

def validate_elf(method, corpus, architecture):
    if is_method(method) is False:
        return {
            'error': method + ' is a valid method, GET /binlex/methods to show valid methods'
        }
    if is_corpus(corpus) is False:
        return {
            'error': corpus + ' is not a valid corpus, GET /binlex/corpra to show valid corpra'
        }
    if is_elf_arch(architecture) is False:
        return {
            'error': architecture + ' is not a valid architecture, GET /binlex/<format>/architectures to show valid architectures'
        }
    return True

def decompile_raw(data, architecture, corpus):
    decompiler = pybinlex.Decompiler()
    if architecture == 'x86':
        decompiler.setup(pybinlex.cs_arch.CS_ARCH_X86, pybinlex.cs_mode.CS_MODE_32, 0)
    if architecture == 'x86_64':
        decompiler.setup(pybinlex.cs_arch.CS_ARCH_X86, pybinlex.cs_mode.CS_MODE_64, 0)
    decompiler.set_threads(app.config['threads'], app.config['thread_cycles'], app.config['thread_sleep'], 0)
    decompiler.set_mode("raw:x86", 0)
    decompiler.set_file_sha256(sha256(data).hexdigest(), 0)
    decompiler.set_corpus(corpus, 0)
    decompiler.decompile(data, 0, 0)
    traits = decompiler.get_traits()
    return traits

def decompile_pe(data, architecture, corpus):
    file_hash = sha256(data).hexdigest()
    pe = pybinlex.PE()
    decompiler = pybinlex.Decompiler()
    if architecture == 'x86':
        pe.setup(pybinlex.MACHINE_TYPES.IMAGE_FILE_MACHINE_I386)
    if architecture == 'x86_64':
        pe.setup(pybinlex.MACHINE_TYPES.IMAGE_FILE_MACHINE_AMD64)
    pe.read_buffer(data)
    sections = pe.get_sections()
    for i in range(0, len(sections)):
        if architecture == 'x86':
            decompiler.setup(pybinlex.cs_arch.CS_ARCH_X86, pybinlex.cs_mode.CS_MODE_32, i)
            decompiler.set_mode("pe:x86", i)
        if architecture == 'x86_64':
            decompiler.setup(pybinlex.cs_arch.CS_ARCH_X86, pybinlex.cs_mode.CS_MODE_64, i)
            decompiler.set_mode("pe:x86_64", i)
        decompiler.set_threads(app.config['threads'], app.config['thread_cycles'], app.config['thread_sleep'], 0)
        decompiler.set_corpus(corpus, i)
        decompiler.set_file_sha256(file_hash, i)
        decompiler.decompile(sections[i]['data'], sections[i]['offset'], i)
    traits = decompiler.get_traits()
    return traits

def decompile_elf(data, architecture, corpus):
    file_hash = sha256(data).hexdigest()
    elf = pybinlex.ELF()
    decompiler = pybinlex.Decompiler()
    if architecture == 'x86':
        elf.setup(pybinlex.ARCH.EM_386)
    if architecture == 'x86_64':
        elf.setup(pybinlex.ARCH.EM_X86_64)
    result = elf.read_buffer(data)
    if result is False:
        return result
    sections = elf.get_sections()
    for i in range(0, len(sections)):
        if architecture == 'x86':
            decompiler.setup(pybinlex.cs_arch.CS_ARCH_X86, pybinlex.cs_mode.CS_MODE_32, i)
            decompiler.set_mode("elf:x86", i)
        if architecture == 'x86_64':
            decompiler.setup(pybinlex.cs_arch.CS_ARCH_X86, pybinlex.cs_mode.CS_MODE_64, i)
            decompiler.set_mode("elf:x86_64", i)
        decompiler.set_corpus(corpus, i)
        decompiler.set_file_sha256(file_hash, i)
        decompiler.set_threads(app.config['threads'], app.config['thread_cycles'], app.config['thread_sleep'], i)
        decompiler.decompile(sections[i]['data'], sections[i]['offset'], i)
    traits = decompiler.get_traits()
    return traits

def publish_traits(traits):
    amqp_channel = app.config['amqp'].channel()
    amqp_channel.queue_declare(queue=app.config['amqp_queue'])
    for trait in traits:
        amqp_channel.basic_publish(exchange='', routing_key=app.config['amqp_queue'], body=json.dumps(trait))

@api.route('/version')
class binlex_version(Resource):
    @require_user
    def get(self):
        """Get the Current Version of Binlex"""
        return {
            'version': pybinlex.__version__
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

@api.route('/samples/<string:corpus>/<string:sha256>')
class binlex_samples(Resource):
    @require_user
    def get(self, corpus, sha256):
        """Download Sample from Corpus"""
        try:
            response = app.config['minio'].download(
                bucket_name=corpus,
                object_name=sha256)
            response = make_response(response.data)
            response.headers['Content-Type'] = 'application/octet-stream'
            return response
        except Exception as error:
            return '', 204
    @require_admin
    def delete(self, corpus, sha256):
        """Delete Sample from Corpus"""
        try:
            response = app.config['minio'].delete(
                bucket_name=corpus,
                object_name=sha256)
            return {
                'success': 'sample deleted'
            }
        except Exception as error:
            return {
                'error': 'file does not exist'
            }, 404

@api.route('/pe/<string:architecture>/<string:method>/<string:corpus>')
class binlex_pe(Resource):
    @require_user
    def post(self, method, corpus, architecture):
        """Get PE Traits"""
        try:
            validate = validate_pe(method, corpus, architecture)
            if validate is not True:
                return validate
            print('decompile')
            traits = decompile_pe(request.data, architecture, corpus)
            if traits is False:
                return {
                    'error': 'decompilation failed'
                }, 400
            if method == 'lex':
                return traits, 200
            if method == 'store':
                print('publish')
                publish_traits(traits)
                print('upload')
                app.config['minio'].upload(
                    bucket_name=corpus,
                    data=request.data)
                return {
                    'success': 'traits added to database queue'
                }, 200
        except Exception as error:
            api.logger.error(error)
            return {
                'error': str(error)
            }, 500

@api.route('/elf/<string:architecture>/<string:method>/<string:corpus>')
class binlex_elf(Resource):
    @require_user
    def post(self, method, corpus, architecture):
        """Get ELF Traits"""
        try:
            validate = validate_elf(method, corpus, architecture)
            if validate is not True:
                return validate
            traits = decompile_elf(request.data, architecture, corpus)
            if traits is False:
                return {
                    'error': 'decompilation failed'
                }, 400
            if method == 'lex':
                return traits
            if method == 'store':
                publish_traits(traits)
                app.config['minio'].upload(
                    bucket_name=corpus,
                    data=request.data)
                return {
                    'success': 'traits added to database queue'
                }, 200
        except Exception as error:
            api.logger.error(error)
            return {
                'error': str(error)
            }, 500

@api.route('/raw/<string:architecture>/<string:method>/<string:corpus>')
class binlex_raw(Resource):
    @require_user
    def post(self, method, corpus, architecture):
        """Get RAW Traits"""
        try:
            validate = validate_raw(method, corpus, architecture)
            if validate is not True:
                return validate
            traits = decompile_raw(request.data, architecture, corpus)
            if method == 'lex':
                return traits, 200
            if method == 'store':
                publish_traits(traits)
                app.config['minio'].upload(
                    bucket_name=corpus,
                    data=request.data)
                return {
                    'success': 'traits added to database queue'
                }, 200
        except Exception as error:
            api.logger.error(error)
            return {
                'error': str(error)
            }, 500

@api.route('/traits/from_files/<string:collection>/<int:limit>/<int:page>')
class binlex_traits_file(Resource):
    @require_user
    def post(self, collection, limit, page):
        """Get Traits via Files Query"""
        if collection not in ['default', 'malware', 'goodware']:
                return {
                    'error': 'collection not supported'
                }, 400
        page = page - 1
        if page < 0:
            return {
                'error': 'page must be greater than 0'
            }, 400
        if limit <= 0:
            return {
                'error': 'limit must be greater than 0'
            }, 400
        data = json.loads(request.data)
        cursor = app.config['mongodb_db']['files']
        docs = cursor.aggregate(
           [
               {
                    "$match": data
                },
                {
                    "$lookup": {
                        "from": collection,
                        "localField": "trait_id",
                        "foreignField": "_id",
                        "as": "trait"
                    }
                },
                {
                    "$unwind": "$trait"
                },
                {
                    "$unset": ["_id", "trait._id", "trait_id"]
                },
                {
                    "$sort": {
                        "sha256" : 1
                    }
                },
                {
                    "$skip": page
                },
                {
                    "$limit": limit
                }
            ]
        )
        results = []
        for doc in docs:
            results.append(jsonify(doc))
        return results

@api.route('/traits/<collection>/<limit>/<page>')
class binlex_traits(Resource):
    @require_user
    def post(self, collection, limit, page):
        """Get Traits by Trait String"""
        try:
            if collection not in ['default', 'malware', 'goodware']:
                return {
                    'error': 'collection not supported'
                }, 400
            data = json.loads(request.data)
            cursor = app.config['mongodb_db'][collection]
            docs = cursor.aggregate(
            [
                {
                        "$match": data
                    },
                    {
                        "$lookup": {
                            "from": 'files',
                            "localField": "_id",
                            "foreignField": "trait_id",
                            "as": "files"
                        }
                    }
                ]
            )
            results = []
            for doc in docs:
                results.append(jsonify(doc))
            return results
        except Exception as error:
            return {
                'error': str(error)
            }, 400