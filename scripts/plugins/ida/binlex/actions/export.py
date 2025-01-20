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
