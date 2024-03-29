#!/usr/bin/env python

import argparse
from flask import Flask, request
from flask_restx import Api, Resource, fields
from hashlib import sha256
from pybinlex import Raw, PE, ELF, Disassembler
from pybinlex import BINARY_ARCH
from pybinlex import BINARY_MODE

BINARY_MODE_32 = BINARY_MODE.BINARY_MODE_32
BINARY_MODE_64 = BINARY_MODE.BINARY_MODE_64
BINARY_ARCH_X86 = BINARY_ARCH.BINARY_ARCH_X86

__author__ = '@c3rb3ru5d3d53c'
__version__ = '1.1.1'

app = Flask(__name__)

api = Api(app)

blapi = api.namespace('', description='Binlex Web API')

def parse_mode(mode):
    try:
        return {
            'type': mode.split(':')[0],
            'arch': mode.split(':')[1]
        }
    except: return None

def parse_tags(tags):
    if tags in ['', None]: return None
    return tags.split(',')

def disasm_pe(corpus, mode, tags, data):
    if mode['arch'] not in ['x86', 'x86_64', 'auto']: return [], 404
    if len(data) <= 0: return 422, []
    f = PE()
    if mode['arch'] == 'x86': f.set_architecture(BINARY_ARCH_X86, BINARY_MODE_32)
    if mode['arch'] == 'x86_64': f.set_architecture(BINARY_ARCH_X86, BINARY_MODE_64)
    f.read_buffer(data)
    d = Disassembler(f)
    d.set_tags([])
    if tags is not None: d.set_tags(tags)
    d.set_corpus(corpus)
    if mode['arch'] != 'auto': d.set_mode(mode['type'] + ':' + mode['arch'])
    d.disassemble()
    return d.get_traits()

def disasm_elf(corpus, mode, tags, data):
    if mode['arch'] not in ['x86', 'x86_64', 'auto']: return [], 404
    f = ELF()
    if mode['arch'] == 'x86': f.set_architecture(BINARY_ARCH_X86, BINARY_MODE_32)
    if mode['arch'] == 'x86_64': f.set_architecture(BINARY_ARCH_X86, BINARY_MODE_64)
    f.read_buffer(data)
    d = Disassembler(f)
    d.set_tags([])
    if tags is not None: d.set_tags(tags)
    d.set_corpus(corpus)
    if mode['arch'] != 'auto': d.set_mode(mode['type'] + ':' + mode['arch'])
    d.disassemble()
    return d.get_traits()

def disasm_raw(corpus, mode, tags, data):
    if mode['arch'] not in ['x86', 'x86_64']: return [], 404
    f = Raw()
    if mode['arch'] == 'x86': f.set_architecture(BINARY_ARCH_X86, BINARY_MODE_32)
    if mode['arch'] == 'x86_64': f.set_architecture(BINARY_ARCH_X86, BINARY_MODE_64)
    f.read_buffer(data)
    d = Disassembler(f)
    d.set_tags([])
    if tags is not None: d.set_tags(tags)
    d.set_corpus(corpus)
    d.set_mode(mode['type'] + ':' + mode['arch'])
    d.disassemble()
    return d.get_traits()

@blapi.route('/api/v1/<corpus>/<mode>')
@blapi.route('/api/v1/<corpus>/<mode>/<tags>')
@blapi.param('mode', 'Trait disassembler mode')
@blapi.param('corpus', 'Corpus name')
@blapi.param('tags', 'List of tags delimited by commas (optional)')
class Disasm(Resource):
    def post(self, corpus, mode, tags=None):
        """
        Disassemble Traits
        """
        mode = parse_mode(mode)
        tags = parse_tags(tags)
        if mode is None: return [], 404
        if corpus in ['', None]: return [], 404
        if len(request.data) <= 0 or request.data is None: return [], 422
        if mode['type'] == 'pe': return disasm_pe(corpus, mode, tags, request.data)
        if mode['type'] == 'elf': return disasm_elf(corpus, mode, tags, request.data)
        if mode['type'] == 'raw': return disasm_raw(corpus, mode, tags, request.data)
        if result is None: return [], 404
        return [], 404

@blapi.route('/api/v1/modes')
class Modes(Resource):
    def get(self):
        """
        List Available Trait Disassemble Modes
        """
        return [
                'pe:x86',
                'pe:x86_64',
                'pe:auto',
                'raw:x86',
                'raw:x86_64',
                'elf:x86',
                'elf:x86_64',
                'elf:auto'
            ], 200

def main():
    parser = argparse.ArgumentParser(
        prog=f'blserver v{__version__}',
        description='Binlex Web API',
        epilog=f'Author: {__author__}'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'v{__version__}'
    )

    parser.add_argument(
        '--host',
        default='127.0.0.1',
        required=False,
        help='Host'
    )

    parser.add_argument(
        '-p',
        '--port',
        default=8080,
        type=int,
        required=False
    )
    parser.add_argument(
        '-d',
        '--debug',
        action='store_true',
        required=False
    )

    args = parser.parse_args()
    
    app.run(debug=args.debug, host=args.host, port=args.port)
