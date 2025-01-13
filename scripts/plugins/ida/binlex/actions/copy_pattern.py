import ida_ua
from lib import IDA
from PyQt5.QtWidgets import QApplication
import ida_kernwin
from binlex.controlflow import Instruction

def execute(parent):
    start_ea, end_ea = IDA.get_disassembly_selection_range()
    pattern = ''
    pc = start_ea
    while pc < end_ea:
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, pc)
        parent.disassemble_instruction(pc, {start_ea: end_ea})
        blinsn = Instruction(pc, parent.cfg)
        pattern += blinsn.chromosome().pattern()
        pc += insn.size
    QApplication.clipboard().setText(pattern)
    ida_kernwin.msg('[*] pattern copied to clipboard\n')
