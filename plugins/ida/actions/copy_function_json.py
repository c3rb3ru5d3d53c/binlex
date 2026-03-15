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
