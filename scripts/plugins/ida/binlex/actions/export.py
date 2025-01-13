import json
from lib import Worker
import ida_kernwin
from lib import IDA

def process(file_path: str, file_attribute: dict, functions: list, function_names: dict) -> str:
    print(f'[-] database exporting to {file_path}...')
    def get_function_symbol_attribute(ea: int, function_names: dict):
        attribute = {}
        attribute['type'] = 'symbol'
        attribute['symbol_type'] = 'function'
        attribute['file_offset'] = None
        attribute['relative_virtual_address'] = None
        attribute['virtual_address'] = ea
        attribute['name'] = function_names[ea]
        attribute['slice'] = None
        return attribute
    with open(file_path, 'w') as file:
        for function in functions:
            j = json.loads(function.json())
            j['attributes'] = []
            j['attributes'].append(file_attribute)
            j['attributes'].append(get_function_symbol_attribute(function.address(), function_names))
            file.write(json.dumps(j) + '\n')
    return file_path

def completed(file_path: str):
    print(f'[*] database exported to {file_path}')

def execute(parent):
    parent.disassemble_controlflow()
    file_path = ida_kernwin.ask_file(1, "*.json", 'Export Binlex Functions to JSON File')
    if not file_path: return
    function_names = IDA().get_function_names()
    worker = Worker(
        target=process,
        args=(
            file_path,
            IDA.file_attribute(),
            parent.cfg.functions(),
            function_names,
        ),
        done_callback=completed
    )
    worker.start()
