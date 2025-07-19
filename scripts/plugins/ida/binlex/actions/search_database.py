import json
from gui import GradientTable
from lib import Worker
from lib import BLClient
from binlex.controlflow import FunctionJsonDeserializer, Function
from gui import SearchDatabaseDialog
from PyQt5.QtWidgets import QDialog
from lib import IDA
from datetime import datetime
from gui import OkayCancelDialog

def process(
    cfg,
    function_addresses,
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

    for address in function_addresses:
        lhs_function = Function(address, cfg)
        lhs_function = FunctionJsonDeserializer(lhs_function.json(), config)
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

            result_data = search_result['data']
            rhs_function = FunctionJsonDeserializer(json.dumps(result_data), config)

            size_ratio = calculate_size_ratio(lhs_function.size(), rhs_function.size())
            if size_ratio < size_ratio_threshold:
                continue

            comparison = lhs_function.compare(rhs_function)
            if comparison is None:
                continue

            minhash_score = comparison.score.minhash()
            if minhash_score is None or minhash_score < minhash_score_threshold:
                continue

            combined_score = (search_result['score'] + minhash_score) / 2.0
            if combined_score < combined_ratio_threshold:
                continue

            row = [
                str(hex(lhs_function.address())),
                str(search_result['score']),
                str(minhash_score),
                str(combined_score),
                str(result_data['size']),
                str(size_ratio),
                str(result_data['number_of_instructions']),
                str(result_data['entropy']),
                str(result_data['average_instructions_per_block']),
                str(result_data['cyclomatic_complexity']),
                function_names[lhs_function.address()],
                search_result['name'],
                search_result['file_attributes']['sha256'],
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
            'Size',
            'Size Ratio',
            'Number of Instructions',
            'Entropy',
            'Average Instructions Per Block',
            'Cyclomatic Complexity',
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
        default_filter_column=11,
        default_sort_column=3,
        default_sort_ascending=False
    )
    def apply_rhs_name(row: list):
        address = int(row[0], 16)
        gnn_score = float(row[1])
        minhash_score = float(row[2])
        score = float(row[3])
        size = int(row[4])
        size_ratio = float(row[5])
        number_of_instructions = int(row[6])
        entropy = float(row[7])
        average_instructions_per_block = float(row[8])
        cyclomatic_complexity = int(row[9])
        rhs_name = row[11]
        sample_sha256 = row[12]
        timestamp = row[13]
        username = row[14]
        IDA().set_name(address, rhs_name)
        comment = (
            "Binlex Function Details:\n"
            f"SHA256: {sample_sha256}\n"
            f"Score: {score}\n"
            f"GNN Score: {gnn_score}\n"
            f"Minhash Score: {minhash_score}\n"
            f"Size: {size}\n"
            f"Size Ratio: {size_ratio}\n"
            f"Number of Instructions: {number_of_instructions}\n"
            f"Entropy: {entropy}\n"
            f"Average Instructions per Block: {average_instructions_per_block}\n"
            f"Cyclomatic Complexity: {cyclomatic_complexity}\n"
            f"Username: {username}\n"
        )
        IDA().set_function_comment(address, comment)

    def apply_lhs_name(row: list):
        address = int(row[0], 16)
        IDA().set_name(address, row[10])
        IDA().delete_function_comment(address)

    def apply_all_names(table: list):
        dialog = OkayCancelDialog(title='Are you sure?', okay_text='Okay', cancel_text='Cancel')
        if dialog.exec_() == QDialog.Rejected: return

        function_names = {}

        for row in table:
            address = int(row[0], 16)
            gnn_score = float(row[1])
            minhash_score = float(row[2])
            score = float(row[3])
            size = int(row[4])
            size_ratio = float(row[5])
            number_of_instructions = int(row[6])
            entropy = float(row[7])
            average_instructions_per_block = float(row[8])
            cyclomatic_complexity = int(row[9])
            rhs_name = row[11]
            sample_sha256 = row[12]
            timestamp = row[13]
            username = row[14]

            if address not in function_names or function_names[address]['score'] < score:
                function_names[address] = {
                    'rhs_name': rhs_name,
                    'sample_sha256': sample_sha256,
                    'score': score,
                    'gnn_score': gnn_score,
                    'minhash_score': minhash_score,
                    'size': size,
                    'size_ratio': size_ratio,
                    'number_of_instructions': number_of_instructions,
                    'entropy': entropy,
                    'average_instructions_per_block': average_instructions_per_block,
                    'cyclomatic_complexity': cyclomatic_complexity,
                    'timestamp': timestamp,
                    'username': username,
                }

        for address, info in function_names.items():
            IDA().set_name(address, info['rhs_name'])
            comment = (
                "Binlex Function Details:\n"
                f"SHA256: {info['sample_sha256']}\n"
                f"Score: {info['score']}\n"
                f"GNN Score: {info['gnn_score']}\n"
                f"Minhash Score: {info['minhash_score']}\n"
                f"Size: {info['size']}\n"
                f"Size Ratio: {info['size_ratio']}\n"
                f"Number of Instructions: {info['number_of_instructions']}\n"
                f"Entropy: {info['entropy']}\n"
                f"Average Instructions per Block: {info['average_instructions_per_block']}\n"
                f"Cyclomatic Complexity: {info['cyclomatic_complexity']}\n"
                f"Username: {info['username']}\n"
            )
            IDA().set_function_comment(address, comment)

    gradient_table.register_row_callback('Apply RHS Name', apply_rhs_name)
    gradient_table.register_row_callback('Apply LHS Name', apply_lhs_name)
    gradient_table.register_table_callback('Apply All RHS Names', apply_all_names)
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
    #functions = parent.get_function_json_deserializers()
    function_addresses = parent.cfg.queue_functions.valid_addresses()
    function_names = parent.ida.get_function_names()
    worker = Worker(
        target=process,
        args=(
            parent.cfg,
            function_addresses,
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
