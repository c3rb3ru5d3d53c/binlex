#!/usr/bin/env python

import pybinlex
from hashlib import sha256
from flask import Blueprint
from flask import current_app as app
from flask import request
from flask_restx import Namespace, Resource, fields

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

@api.route('/<string:method>/<string:corpus>/pe/<string:architecture>/')
class binlex_pe(Resource):
    def post(self, method, corpus, architecture):
        """Process PE"""
        return 'Placeholder'

@api.route('/<string:method>/<string:corpus>/elf/<string:architecture>')
class binlex_elf(Resource):
    def post(self, method, corpus, architecture):
        """Process ELF"""
        return 'Placeholder'

@api.route('/<string:method>/<string:corpus>/raw/<string:architecture>')
class binlex_raw(Resource):
    def post(self, method, corpus, architecture):
        """Process Shellcode"""
        validate = validate_raw(method, corpus, architecture)
        if validate is not True:
            return validate
        data = request.data
        decompiler = pybinlex.Decompiler()
        if architecture == 'x86':
            decompiler.setup(pybinlex.cs_arch.CS_ARCH_X86, pybinlex.cs_mode.CS_MODE_32, 0)
        if architecture == 'x86_64':
            decompiler.setup(pybinlex.cs_arch.CS_ARCH_X86, pybinlex.cs_mode.CS_MODE_64, 0)
        decompiler.set_threads(app.config['threads'], 1, 500, 0)
        decompiler.set_blmode("raw:x86", 0)
        decompiler.set_file_sha256(sha256(data).hexdigest(), 0)
        decompiler.decompile(data, 0, 0)
        if method == 'lex':
            traits = decompiler.get_traits()
            return traits, 200
        if method == 'store':
            return {
                'error': 'not implemented'
            }, 404
