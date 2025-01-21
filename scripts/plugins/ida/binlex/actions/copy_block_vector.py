from lib import Worker
from lib import BLClient
from lib import IDA
from PyQt5.QtWidgets import QDialog
from binlex.controlflow import Function, Block
from gui import BinlexServerAuthenticationDialog
from PyQt5.QtWidgets import QApplication
import ida_kernwin

def execute(parent):
    dialog = BinlexServerAuthenticationDialog()
    if dialog.exec_() != QDialog.Accepted: return
    (
        url,
        api_key,
    ) = dialog.get_inputs()
    ea = IDA().get_screen_ea()
    bb = IDA().get_basic_block(ea)
    parent.disassemble_block(bb)
    block = Block(bb.start_ea, parent.cfg)
    client = BLClient(url=url, api_key=api_key)
    status, vector = client.inference(block.to_dict())
    if status != 200: return
    QApplication.clipboard().setText(str(vector))
    ida_kernwin.msg(f'[*] block vector at {hex(bb.start_ea)} copied to clipboard\n')
