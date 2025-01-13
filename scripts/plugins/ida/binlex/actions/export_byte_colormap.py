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
