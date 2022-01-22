#!/usr/bin/env python

import logging
import pybinlex
from hashlib import sha256
from flask import Blueprint
from flask import current_app as app
from flask import request
from flask_restx import Namespace, Resource, fields

logger = logging.getLogger(__name__)

api = Namespace('binlex', description='Binlex Upload API')

methods = ['store', 'lex']

pe_architectures = ['x86', 'x86_64']

elf_architectures = ['x86', 'x86_64']

raw_architectures = ['x86', 'x86_64']

corpra = ['default', 'malware', 'goodware']

def is_corpus(corpus):
    if corpus in corpra:
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

def decompile_raw(data, architecture):
    decompiler = pybinlex.Decompiler()
    if architecture == 'x86':
        decompiler.setup(pybinlex.cs_arch.CS_ARCH_X86, pybinlex.cs_mode.CS_MODE_32, 0)
    if architecture == 'x86_64':
        decompiler.setup(pybinlex.cs_arch.CS_ARCH_X86, pybinlex.cs_mode.CS_MODE_64, 0)
    decompiler.set_threads(app.config['threads'], 1, 500, 0)
    decompiler.set_blmode("raw:x86", 0)
    decompiler.set_file_sha256(sha256(data).hexdigest(), 0)
    decompiler.decompile(data, 0, 0)
    traits = decompiler.get_traits()
    return traits

@api.route('/version')
class binlex_version(Resource):
    def get(self):
        return {
            'version': pybinlex.__version__
        }

@api.route('/methods')
class binlex_methods(Resource):
    def get(self):
        return methods

@api.route('/pe/architectures')
class binlex_pe_architectures(Resource):
    def get(self):
        return pe_architectures

@api.route('/elf/architectures')
class binlex_elf_architectures(Resource):
    def get(self):
        return elf_architectures

@api.route('/raw/architectures')
class binlex_raw_architectures(Resource):
    def get(self):
        return raw_architectures

@api.route('/corpra')
class binlex_corpra(Resource):
    def get(self):
        return corpra

@api.route('/pe/<string:architecture>/<string:method>/<string:corpus>')
class binlex_pe(Resource):
    def post(self, method, corpus, architecture):
        """Get PE Traits"""
        return 'Placeholder'

@api.route('/pe/<string:architecture>/<string:method>/<string:corpus>/yara')
class binlex_PE_yara(Resource):
    def post(self, method, corpus, architecture):
        """Get PE Traits and YARA Matches"""
        return 'Placeholder'

@api.route('/elf/<string:architecture>/<string:method>/<string:corpus>')
class binlex_elf(Resource):
    def post(self, method, corpus, architecture):
        """Get ELF Traits"""
        return 'Placeholder'

@api.route('/elf/<string:architecture>/<string:method>/<string:corpus>/yara')
class binlex_elf_yara(Resource):
    def post(self, method, corpus, architecture):
        """Get ELF Traits and YARA Matches"""
        return 'Placeholder'

@api.route('/raw/<string:architecture>/<string:method>/<string:corpus>')
class binlex_raw(Resource):
    def post(self, method, corpus, architecture):
        """Get RAW Traits"""
        try:
            validate = validate_raw(method, corpus, architecture)
            if validate is not True:
                return validate
            traits = decompile_raw(request.data, architecture)
            if method == 'lex':
                return traits, 200
            if method == 'store':
                return {
                    'error': 'not implemented'
                }, 404
        except Exception as error:
            logger.error(error)

@api.route('/raw/<string:architecture>/<string:method>/<string:corpus>/yara')
class binlex_raw_yara(Resource):
    def post(self, method, corpus, architecture):
        """Get RAW Traits and YARA Matches"""
        return 'Placeholder'