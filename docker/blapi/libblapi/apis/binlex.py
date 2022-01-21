#!/usr/bin/env python

from flask import Blueprint
from flask import current_app as app
from flask_restx import Namespace, Resource, fields

api = Namespace('binlex', description='Binlex Upload API')

@api.route('/pe/x86')
class binlex_pe_x86(Resource):
    def post(self):
        """Upload PE x86"""
        return 'Placeholder'

@api.route('/pe/x86_64')
class binlex_pe_x86_64(Resource):
    def post(self):
        """Upload PE x86_64"""
        return 'Placeholder'

@api.route('/elf/x86')
class binlex_elf_x86(Resource):
    def post(self):
        """Upload ELF x86"""
        return 'Placeholder'

@api.route('/elf/x86_64')
class binlex_elf_x86(Resource):
    def post(self):
        """Upload ELF x86_64"""
        return 'Placeholder'

@api.route('/raw/x86')
class binlex_raw_x86(Resource):
    def post(self):
        """Upload Shellcode x86"""
        return 'Placeholder'

@api.route('/raw/x86_64')
class binlex_raw_x86_64(Resource):
    def post(self):
        """Upload Shellcode x86_64"""
        return 'Placeholder'