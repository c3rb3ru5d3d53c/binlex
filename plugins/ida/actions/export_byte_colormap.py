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

import ida_kernwin
import idc
import idautils
from lib import IDA
from binlex.imaging import ColorMap

def execute(parent):
    file_path = ida_kernwin.ask_file(1, "*.svg", 'Export Binlex Byte ColorMap')
    if not file_path: return
    print(f'[-] creating byte colormap...')
    colormap = ColorMap()
    segments = []
    for seg_ea in idautils.Segments():
        start = idc.get_segm_start(seg_ea)
        end = idc.get_segm_end(seg_ea)
        segments.append((start, end))
    segments.sort(key=lambda x: x[0], reverse=True)
    for start, end in segments:
        data = IDA.get_bytes(start, end - start)
        colormap.append(data, offset=start)
    colormap.write(file_path)
    print(f'[*] wrote byte colormap to {file_path}')
