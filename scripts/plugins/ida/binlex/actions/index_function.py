from lib import Worker
from gui import BinlexServerSettingsDialog
from lib import BLClient
from PyQt5.QtWidgets import QDialog
from binlex.controlflow import Function
from lib import IDA

def process(client, data: dict, include_blocks: bool, database: str):
    status, vector = client.index(
        database=database,
        collection='function',
        partition=data['architecture'],
        data=data
    )

    if status != 200:
        print(f'[-] warning: {vector}')

    if not include_blocks: return

    for block in data['blocks']:
        status, vector = client.index(
            database=database,
            collection='block',
            partition=block['architecture'],
            data=block
        )

        if status != 200:
            print(f'[-] warning: {vector}')

def complete():
    print('[*] indexed function')

def execute(parent):
    dialog = BinlexServerSettingsDialog()
    if dialog.exec_() != QDialog.Accepted: return
    (
        url,
        api_key,
        database,
        include_blocks,
    ) = dialog.get_inputs()
    ea = IDA().get_screen_ea()
    f = IDA().get_function(ea)
    parent.disassemble_function(f)
    function = Function(f.start_ea, parent.cfg)
    data = function.to_dict()
    data['attributes'] = IDA().get_function_attributes(f)
    file_attribute = IDA().file_attribute()
    for i in range(0, len(data['blocks'])):
        data['blocks'][i]['attributes'] = [file_attribute]
    client = BLClient(url=url, api_key=api_key)
    worker = Worker(
        target=process,
        args=(
            client,
            data,
            include_blocks,
            database,
        ),
        done_callback=complete,
    )
    worker.start()
    print(f'[-] indexing function at {hex(f.start_ea)}...')
