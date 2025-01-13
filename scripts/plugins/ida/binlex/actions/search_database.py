import json
from gui import GradientTable
from lib import Worker
from lib import BLClient
from binlex.controlflow import FunctionJsonDeserializer
from gui import SearchDatabaseDialog
from PyQt5.QtWidgets import QDialog
from lib import IDA
from datetime import datetime

def process(
    functions: list,
    client: BLClient,
    config,
    function_names: dict,
    database: str = 'default',
    minhash_score_threshold: float = 0.75,
    gnn_similarity_threshold: float = 0.75,
    size_ratio_threshold: float = 0.75,
    combined_ratio_threshold: float = 0.75,
    mininum_size: int = 32,
    chromosome_minhash_ratio_threshold: float = 0.75,
    limit: int = 3,
    exclude_named_functions: bool = False,
):
    print('[-] database search started...')
    def calculate_size_ratio(len1: int, len2: int) -> float:
        if max(len1, len2) == 0:
            return 1.0
        return 1 - (abs(len1 - len2) / max(len1, len2))

    results_table = []

    for lhs_function in functions:
        if exclude_named_functions and not function_names[lhs_function.address()].startswith('sub_'):
            continue

        if lhs_function.size() < mininum_size:
            continue

        if lhs_function.chromosome_minhash_ratio() < chromosome_minhash_ratio_threshold:
            continue

        status, lhs_vector = client.inference(lhs_function.to_dict())
        if status != 200:
            return

        status, search_results = client.search(
            database=database,
            collection='function',
            partition=lhs_function.architecture().to_string(),
            offset=0,
            limit=limit,
            threshold=gnn_similarity_threshold,
            vector=lhs_vector
        )
        if status != 200:
            print(f"[x] status: {status}, response: {search_results}")
            return

        for search_result in search_results:
            if len(search_result['name']) == 0:
                continue

            gnn_similarity = min(search_result['score'], 1.0)
            if gnn_similarity < gnn_similarity_threshold:
                continue

            rhs_function = FunctionJsonDeserializer(json.dumps(search_result['data']), config)

            size_ratio = calculate_size_ratio(lhs_function.size(), rhs_function.size())
            if size_ratio < size_ratio_threshold:
                continue

            comparison = lhs_function.compare(rhs_function)
            if comparison is None:
                continue

            minhash_score = comparison.score.minhash()
            if minhash_score is None or minhash_score < minhash_score_threshold:
                continue

            combined_score = (gnn_similarity + minhash_score) / 2.0
            if combined_score < combined_ratio_threshold:
                continue

            row = [
                str(hex(lhs_function.address())),
                str(gnn_similarity),
                str(minhash_score),
                str(combined_score),
                str(size_ratio),
                function_names[lhs_function.address()],
                search_result['name'],
                search_result['sha256'],
                datetime.fromtimestamp(search_result['timestamp']).isoformat(),
                search_result['username'],
                str(lhs_vector),
                search_result['vector']
            ]
            results_table.append(row)

    return results_table

def complete(table: list):
    print('[-] database search completed')
    gradient_table = GradientTable(
        table,
        [
            'LHS Address',
            'GNN Score',
            'Minhash Score',
            'Combined Score',
            'Size Ratio',
            'LHS Name',
            'RHS Name',
            'RHS SHA256',
            'Timestamp',
            'Username',
            'LHS Vector',
            'RHS Vector',
        ],
        color_column=3,
        min_value=0,
        max_value=1,
        low_to_high=True,
        default_filter_column=5,
        default_sort_column=3,
        default_sort_ascending=False
    )
    def apply_rhs_name(row: list):
        IDA().set_name(int(row[0], 16), row[6])
    def apply_lhs_name(row: list):
        IDA().set_name(int(row[0], 16), row[5])
    gradient_table.register_row_callback('Apply RHS Name', apply_rhs_name)
    gradient_table.register_row_callback('Apply LHS Name', apply_lhs_name)
    gradient_table.Show('Binlex Function Compare Results')

def execute(parent):
    dialog = SearchDatabaseDialog()
    if dialog.exec_() != QDialog.Accepted: return
    (
        minhash_score_threshold,
        mininum_size,
        size_ratio_threshold,
        chromosome_minhash_ratio_threshold,
        combined_ratio_threshold,
        gnn_similarity_threshold,
        url,
        api_key,
        database,
        limit,
        exclude_named_functions,
    ) = dialog.get_inputs()
    client = BLClient(url=url, api_key=api_key)
    IDA().set_registry_value('url', url)
    IDA().set_registry_value('api_key', api_key)
    parent.disassemble_controlflow()
    functions = parent.get_function_json_deserializers()
    function_names = parent.ida.get_function_names()
    worker = Worker(
        target=process,
        args=(
            functions,
            client,
            parent.config,
            function_names,
            database,
            minhash_score_threshold,
            gnn_similarity_threshold,
            size_ratio_threshold,
            combined_ratio_threshold,
            mininum_size,
            chromosome_minhash_ratio_threshold,
            limit,
            exclude_named_functions,
        ),
        done_callback=complete,
    )
    worker.start()
