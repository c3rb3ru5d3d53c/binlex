import ida_bytes
from ida import IDA
from PyQt5.QtWidgets import QApplication
import ida_kernwin
from binlex.controlflow import Instruction
from binlex.hashing import MinHash32

def execute(parent):
    start_ea, end_ea = IDA.get_disassembly_selection_range()
    data = ida_bytes.get_bytes(start_ea, end_ea - start_ea)
    minhash = MinHash32(
        data,
        parent.config.instructions.hashing.minhash.number_of_hashes,
        parent.config.instructions.hashing.minhash.shingle_size,
        parent.config.instructions.hashing.minhash.seed).hexdigest()
    if minhash is None:
        ida_kernwin.msg('[x] not enough data or minhash failed\n')
        return
    QApplication.clipboard().setText(minhash)
    ida_kernwin.msg(f'[*] copied minhash to clipboard based on {len(data)} bytes\n')