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

from lib import Worker
from gui import BinlexServerSettingsDialog
from lib import BLClient
from PyQt5.QtWidgets import QDialog
from binlex.controlflow import Function, Block

def process(client, cfg, function_addresses: list, function_attributes: dict, block_addresses: list, block_attributes: dict, database: str):
    for address in function_addresses:
        function = Function(address, cfg)
        data = function.to_dict()
        data['attributes'] = function_attributes[address]
        status, vector = client.index(
            database=database,
            collection='function',
            partition=data['architecture'],
            data=data
        )
        if status != 200:
            print(f'[-] warning: {vector}')

    for address in block_addresses:
        block = Block(address, cfg)
        data = block.to_dict()
        data['attributes'] = block_attributes[address]
        status, vector = client.index(
            database=database,
            collection='block',
            partition=data['architecture'],
            data=data
        )
        if status != 200:
            print(f'[-] warning: {vector}')

def complete():
    print('[*] indexed database')

def execute(parent):
    dialog = BinlexServerSettingsDialog()
    if dialog.exec_() != QDialog.Accepted: return
    (
        url,
        api_key,
        database,
        include_blocks,
    ) = dialog.get_inputs()
    client = BLClient(url=url, api_key=api_key)
    parent.disassemble_controlflow()
    function_attributes = parent.get_function_attributes()
    function_addresses = parent.cfg.queue_functions.valid_addresses()
    if include_blocks:
        block_attributes = parent.get_block_attributes()
        block_addresses = parent.cfg.queue_blocks.valid_addresses()
    else:
        block_attributes = []
        block_addresses = []
    worker = Worker(
        target=process,
        args=(
            client,
            parent.cfg,
            function_addresses,
            function_attributes,
            block_addresses,
            block_attributes,
            database,
        ),
        done_callback=complete,
    )
    worker.start()
    print('[-] started database indexing...')
