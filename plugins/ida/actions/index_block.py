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
from binlex.controlflow import Block
from lib import IDA

def process(client, data: dict, database: str):
    status, vector = client.index(
        database=database,
        collection='block',
        partition=data['architecture'],
        data=data
    )

    if status != 200:
        print(f'[-] warning: {vector}')

def complete():
    print('[*] indexed block')

def execute(parent):
    dialog = BinlexServerSettingsDialog(show_include_blocks=False)
    if dialog.exec_() != QDialog.Accepted: return
    (
        url,
        api_key,
        database,
        _,
    ) = dialog.get_inputs()
    ea = IDA().get_screen_ea()
    bb = IDA().get_basic_block(ea)
    parent.disassemble_block(bb)
    block = Block(bb.start_ea, parent.cfg)
    data = block.to_dict()
    data['attributes'] = [IDA().file_attribute()]
    client = BLClient(url=url, api_key=api_key)
    worker = Worker(
        target=process,
        args=(
            client,
            data,
            database,
        ),
        done_callback=complete,
    )
    worker.start()
    print(f'[-] indexing block at {hex(bb.start_ea)}...')
