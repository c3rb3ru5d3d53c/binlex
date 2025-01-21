from lib import IDA
from binlex.controlflow import Function
from PyQt5.QtWidgets import QApplication
import ida_kernwin
import json

def execute(parent):
    ea = IDA().get_screen_ea()
    bb = IDA().get_basic_block(ea)
    f = IDA().get_function(ea)
    parent.disassemble_function(f)
    function = Function(f.start_ea, parent.cfg)
    data = function.to_dict()
    data['attributes'] = IDA().get_function_attributes(f)
    QApplication.clipboard().setText(json.dumps(data))
    ida_kernwin.msg(f'[*] function json at {hex(f.start_ea)} copied to clipboard\n')
