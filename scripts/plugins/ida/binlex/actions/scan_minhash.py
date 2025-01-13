import idaapi
from PyQt5.QtWidgets import QDialog
from lib import IDA
from binlex.hashing import MinHash32
from gui import Progress
from gui import GradientTable
from gui import ScanMinHashInputDialog
from lib import Worker

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
        similarity = MinHash32.compare(lhs_minhash, rhs_minhash)
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
