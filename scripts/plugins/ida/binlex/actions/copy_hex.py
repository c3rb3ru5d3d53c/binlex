import ida_kernwin
import ida_bytes
from ida import IDA
from PyQt5.QtWidgets import QApplication

def execute(parent):
    start_ea, end_ea = IDA.get_disassembly_selection_range()
    pattern = ida_bytes.get_bytes(start_ea, end_ea - start_ea).hex()
    QApplication.clipboard().setText(pattern)
    ida_kernwin.msg('[*] hex copied to clipboard\n')