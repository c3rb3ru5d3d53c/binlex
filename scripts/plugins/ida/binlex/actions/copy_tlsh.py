import ida_bytes
from lib import IDA
from PyQt5.QtWidgets import QApplication
import ida_kernwin
from binlex.hashing import TLSH

def execute(parent):
    start_ea, end_ea = IDA.get_disassembly_selection_range()
    data = ida_bytes.get_bytes(start_ea, end_ea - start_ea)
    tlsh = TLSH(data).hexdigest(50)
    if tlsh is None:
        ida_kernwin.msg('[x] not enough data or minhash failed\n')
        return
    QApplication.clipboard().setText(tlsh)
    ida_kernwin.msg(f'[*] copied tlsh to clipboard based on {len(data)} bytes\n')
