import idaapi
from PyQt5.QtWidgets import QDialog
from ida import IDA
from binlex.hashing import MinHash32
from gui import Progress
from gui import GradientTable
from gui import ScanMinHashInputDialog

def execute(parent):
        dialog = ScanMinHashInputDialog()
        if dialog.exec_() != QDialog.Accepted: return
        rhs_minhash, num_bytes, threshold = dialog.get_inputs()
        table = []
        addresses = IDA.get_instruction_addresses()
        progress = Progress(max_value=len(addresses))
        progress.show()
        for addr in addresses:
            if progress.is_closed: return
            progress.increment()
            data = idaapi.get_bytes(addr, num_bytes)
            lhs_minhash = MinHash32(
                data,
                parent.config.instructions.hashing.minhash.number_of_hashes,
                parent.config.instructions.hashing.minhash.shingle_size,
                parent.config.instructions.hashing.minhash.seed).hexdigest()
            similarity = MinHash32.compare(lhs_minhash, rhs_minhash)
            if similarity is not None and similarity > threshold:
                row = []
                row.append(str(hex(addr)))
                row.append(parent.value_to_string(similarity))
                row.append(lhs_minhash)
                row.append(rhs_minhash)
                table.append(row)
        progress.close()
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
            min_value=threshold,
            max_value=1,
            low_to_high=True,
            default_filter_column=0,
            default_sort_column=1,
            default_sort_ascending=False)
        form.Show('Binlex MinHash Scan Table')
