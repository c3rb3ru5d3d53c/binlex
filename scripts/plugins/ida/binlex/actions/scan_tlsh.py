import idaapi
from PyQt5.QtWidgets import QDialog
from lib import IDA
from binlex.hashing import TLSH
from gui import Progress, GradientTable, ScanTLSHInputDialog
from lib import Worker

def process(rhs_tlsh, num_bytes, threshold, addresses, config) -> list:
    print(f'[-] processing tlsh scan...')
    table = []
    for addr in addresses:
        data = IDA().get_bytes(addr, num_bytes)
        if not data: continue

        lhs_tlsh = TLSH(data).hexdigest(50)
        if lhs_tlsh is None: continue

        similarity = TLSH.compare(lhs_tlsh, rhs_tlsh)
        if similarity is not None and similarity < threshold:
            table.append([
                str(hex(addr)),
                str(similarity) if similarity is not None else '',
                rhs_tlsh,
                lhs_tlsh
            ])
    return table

def complete(table: list):
    print(f'[*] completed tlsh scan')
    headers = ['Address', 'Score', 'TLSH LHS', 'TLSH RHS']
    form = GradientTable(
        table,
        headers,
        color_column=1,
        min_value=512,
        max_value=0,
        low_to_high=True,
        default_filter_column=0,
        default_sort_column=1,
        default_sort_ascending=True
    )
    form.Show('Binlex TLSH Scan Table')

def execute(parent):
    dialog = ScanTLSHInputDialog()
    if dialog.exec_() != QDialog.Accepted:
        return

    rhs_tlsh, num_bytes, threshold = dialog.get_inputs()
    addresses = IDA.get_instruction_addresses()
    worker = Worker(
        target=process,
        args=(
            rhs_tlsh,
            num_bytes,
            threshold,
            addresses,
            parent.config
        ),
        done_callback=complete
    )
    worker.start()
