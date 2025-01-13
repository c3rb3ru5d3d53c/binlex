from lib import Worker
from gui import BinlexServerSettingsDialog
from lib import BLClient
from PyQt5.QtWidgets import QDialog

def process(client, functions: list, database: str):
    for function in functions:
        status, vector = client.index(
            database=database,
            collection='function',
            partition=function.architecture().to_string(),
            data=function.to_dict()
        )
        if status != 200: return

def complete():
    print('[*] indexed database')

def execute(parent):
    dialog = BinlexServerSettingsDialog()
    if dialog.exec_() != QDialog.Accepted: return
    (
        url,
        api_key,
        database,
    ) = dialog.get_inputs()
    client = BLClient(url=url, api_key=api_key)
    parent.disassemble_controlflow()
    functions = parent.get_function_json_deserializers()
    worker = Worker(
        target=process,
        args=(
            client,
            functions,
            database,
        ),
        done_callback=complete,
    )
    worker.start()
    print('[-] started database indexing...')
