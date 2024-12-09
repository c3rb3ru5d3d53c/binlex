#A Ghidra to Binlex Tool
#@author @c3rb3ru5d3d53c
#@category
#@keybinding
#@menupath
#@toolbar

import json

for function in currentProgram().getFunctionManager().getFunctions(True):
    print(json.dumps({
        'type': 'symbol',
        'symbol_type': 'function',
        'name': function.getName(),
        'file_offset': None,
        'relative_virtual_address': None,
        'virtual_address': function.getEntryPoint().getOffset()
    }))
