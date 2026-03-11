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

import idaapi
from PyQt5.QtWidgets import QDialog
from lib import IDA
from binlex.hashing import MinHash32
from gui import Progress
from gui import GradientTable
from gui import ScanMinHashInputDialog
from lib import Worker

def compare_minhash(lhs_minhash: str, rhs_minhash: str) -> float:
    if len(lhs_minhash) != len(rhs_minhash) or len(lhs_minhash) % 8 != 0:
        return 0.0
    lhs_chunks = [lhs_minhash[i:i + 8] for i in range(0, len(lhs_minhash), 8)]
    rhs_chunks = [rhs_minhash[i:i + 8] for i in range(0, len(rhs_minhash), 8)]
    if not lhs_chunks:
        return 0.0
    matches = sum(1 for lhs, rhs in zip(lhs_chunks, rhs_chunks) if lhs == rhs)
    return matches / len(lhs_chunks)

def process(rhs_minhash, num_bytes, threshold, addresses, config):
    print(f'[-] processing minhash scan...')
    table = []
    for addr in addresses:
        data = IDA().get_bytes(addr, num_bytes)
        lhs_minhash = MinHash32(
            data,
            config.instructions.hashing.minhash.number_of_hashes,
            config.instructions.hashing.minhash.shingle_size,
            config.instructions.hashing.minhash.seed
        ).hexdigest()
        similarity = compare_minhash(lhs_minhash, rhs_minhash)
        if similarity is not None and similarity > threshold:
            row = [
                str(hex(addr)),
                similarity or '',
                lhs_minhash,
                rhs_minhash
            ]
            table.append(row)
    return table

def complete(table: list):
    print(f'[*] completed minhash scan')
    headers = [
        'Address',
        'Score',
        'MinHash LHS',
        'MinHash RHS',
    ]
    form = GradientTable(
        table,
        headers,
        color_column=1,
        min_value=0,
        max_value=1,
        low_to_high=True,
        default_filter_column=0,
        default_sort_column=1,
        default_sort_ascending=False
    )
    form.Show('Binlex MinHash Scan Table')

def execute(parent):
    dialog = ScanMinHashInputDialog()
    if dialog.exec_() != QDialog.Accepted: return
    rhs_minhash, num_bytes, threshold = dialog.get_inputs()
    addresses = IDA.get_instruction_addresses()
    worker = Worker(
        target=process,
        args=(
            rhs_minhash,
            num_bytes,
            threshold,
            addresses,
            parent.config
        ),
        done_callback=complete
    )
    worker.start()
