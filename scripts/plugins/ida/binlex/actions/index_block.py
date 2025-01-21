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
