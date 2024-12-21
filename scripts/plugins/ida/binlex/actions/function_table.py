from ida import IDA
from gui import GradientTable

def execute(parent):
    if parent.table_window: return None
    parent.disassemble_controlflow()
    data = []
    for function in parent.cfg.functions():
        chromosome = function.chromosome()
        row = []
        row.append(str(hex(function.address)))
        row.append(IDA.get_function_name(function.address))
        row.append("function")
        row.append(function.is_contiguous())
        row.append(function.size())
        row.append(function.number_of_blocks())
        row.append(function.cyclomatic_complexity())
        row.append(function.average_instructions_per_block())
        row.append(parent.value_to_string(function.chromosome_minhash_ratio()))
        if chromosome is not None:
            row.append(parent.value_to_string(chromosome.minhash()))
        else:
            row.append(parent.value_to_string(None))
        row.append(parent.value_to_string(function.chromosome_tlsh_ratio()))
        if chromosome is not None:
            row.append(parent.value_to_string(chromosome.tlsh()))
        else:
            row.append(parent.value_to_string(None))
        if chromosome is not None:
            row.append(parent.value_to_string(function.chromosome().pattern()))
        else:
            row.append(parent.value_to_string(None))
        data.append(row)
    headers = [
        'Address',
        'Name',
        'Type',
        'Contiguous',
        'Size',
        'Number of Blocks',
        'Cyclomatic Complexity',
        'Average Instructions Per Block',
        'Minhash Chromosome Ratio',
        'Chromosome Minhash',
        'TLSH Chromosome Ratio',
        'Chromosome TLSH',
        'Chromosome Pattern']
    form = GradientTable(
        data,
        headers,
        color_column=7,
        min_value=0,
        max_value=1,
        low_to_high=True,
        default_filter_column=1,
        default_sort_column=5,
        default_sort_ascending=False)
    form.Show('Binlex Function Table')