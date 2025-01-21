from lib import Worker
from lib import BLClient
from lib import IDA
from PyQt5.QtWidgets import QDialog
from binlex.controlflow import Function, Block
from gui import BinlexServerAuthenticationDialog
from PyQt5.QtWidgets import QApplication
import ida_kernwin
import json

def execute(parent):
    ea = IDA().get_screen_ea()
    bb = IDA().get_basic_block(ea)
    parent.disassemble_block(bb)
    block = Block(bb.start_ea, parent.cfg)
    data = block.to_dict()
    data['attributes'] = [IDA().file_attribute()]
    QApplication.clipboard().setText(json.dumps(data))
    ida_kernwin.msg(f'[*] block json at {hex(bb.start_ea)} copied to clipboard\n')
