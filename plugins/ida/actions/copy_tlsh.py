# MIT License
#
# Copyright (c) [2025] [c3rb3ru5d3d53c]
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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
