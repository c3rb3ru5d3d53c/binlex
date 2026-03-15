# MIT License
#
# Copyright (c) [2025] [c3rb3ru5d3d53c]
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import json
from lib import Worker
import ida_kernwin
from lib import IDA
from binlex.controlflow import Function

def process(file_path: str, cfg, function_addresses: list, function_attributes: dict, function_names: dict) -> str:
    print(f'[-] database exporting to {file_path}...')
    with open(file_path, 'w') as file:
        for address in function_addresses:
            function = Function(address, cfg)
            data = function.to_dict()
            data['attributes'] = function_attributes[address]
            file.write(json.dumps(data) + '\n')
    return file_path

def completed(file_path: str):
    print(f'[*] database exported to {file_path}')

def execute(parent):
    parent.disassemble_controlflow()
    file_path = ida_kernwin.ask_file(1, "*.json", 'Export Binlex Functions to JSON File')
    if not file_path: return
    function_names = IDA().get_function_names()
    function_attributes = parent.get_function_attributes()
    function_addresses = parent.cfg.queue_functions.valid_addresses()
    worker = Worker(
        target=process,
        args=(
            file_path,
            parent.cfg,
            function_addresses,
            function_attributes,
            function_names,
        ),
        done_callback=completed
    )
    worker.start()
