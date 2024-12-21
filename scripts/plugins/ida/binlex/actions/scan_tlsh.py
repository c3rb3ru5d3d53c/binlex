import idaapi
from PyQt5.QtWidgets import QDialog
from ida import IDA
from binlex.hashing import TLSH
from gui import Progress
from gui import GradientTable
from gui import ScanTLSHInputDialog

def execute(parent):
        dialog = ScanTLSHInputDialog()
        if dialog.exec_() != QDialog.Accepted: return
        rhs_tlsh, num_bytes, threshold = dialog.get_inputs()
        table = []
        addresses = IDA.get_instruction_addresses()
        progress = Progress(max_value=len(addresses))
        progress.show()
        for addr in addresses:
            if progress.is_closed: return
            progress.increment()
            data = idaapi.get_bytes(addr, num_bytes)
            lhs_tlsh = TLSH(data).hexdigest(50)
            if lhs_tlsh is None: continue
            similarity = TLSH.compare(lhs_tlsh, rhs_tlsh)
            if similarity is not None and similarity < threshold:
                row = []
                row.append(str(hex(addr)))
                row.append(parent.value_to_string(similarity))
                row.append(rhs_tlsh)
                row.append(lhs_tlsh)
                table.append(row)
        progress.close()
        headers = [
            'Address',
            'Score',
            'TLSH LHS',
            'TLSH RHS',
        ]
        form = GradientTable(
            table,
            headers,
            color_column=1,
            min_value=threshold,
            max_value=0,
            low_to_high=True,
            default_filter_column=0,
            default_sort_column=1,
            default_sort_ascending=True)
        form.Show('Binlex TLSH Scan Table')