#!/usr/bin/env python
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

import json, argparse, sys

from binlex.formats import PE
from binlex.disassemblers.capstone import Disassembler
from binlex.controlflow import Graph, Function, FunctionJsonDeserializer
from blclient import BLClient
from binlex import Config


def calculate_size_ratio(len1: int, len2: int) -> float:
    if max(len1, len2) == 0:
        return 1.0
    return 1 - (abs(len1 - len2) / max(len1, len2))

def main(args):

    config = Config()
    config.general.threads = 16
    
    pe = PE(args.file, config)
    img = pe.image()
    mmap = img.mmap()
    disasm = Disassembler(pe.architecture(), mmap, pe.executable_virtual_address_ranges(), config)
    cfg = Graph(pe.architecture(), config)
    disasm.disassemble_controlflow(pe.entrypoint_virtual_addresses(), cfg)
    
    bl_func = Function(int(args.address),cfg)
    
    client = BLClient(url=args.url, api_key=args.api)
    status, databases = client.databases()
    
    if status != 200:
        print(f"Connection to {args.url} with the api key {args.api} resulted in HTTP status {status}")
        sys.exit(1)
    
    if args.database not in databases:
        print(f"Database {args.database} not found. Available databases: {databases}")
        sys.exit(1)
    
    # Search using just an address and SHA256 of the sample as a query usage example
    query = f"file_attributes['sha256'] == '{pe.sha256()}' and address == {args.address}"
    status, search_addr_results = client.query(
                database=args.database,
                collection="function",
                partition=pe.architecture(),
                query=query,
                offset=0,
                limit=15
            )
    # Print raw results
    print(search_addr_results)
    
    # Search using GNN vector and verify similarity with minhash and size check
    status, vector = client.inference(bl_func.to_dict())
    gnn_similarity_threshold: float = 0.75
    size_ratio_threshold: float = 0.75
    combined_ratio_threshold: float = 0.75
    minhash_score_threshold: float = 0.75
    limit: int = 3
    status, search_vector_results = client.search(
                database=args.database,
                collection='function',
                partition=pe.architecture(),
                offset=0,
                limit=limit, # Maximum number of results to return
                query=f"file_attributes['sha256'] != '{pe.sha256()}'", # An example query to go with vector search
                threshold=gnn_similarity_threshold,
                vector=vector
            )


    vector_results = []
    for search_result in search_vector_results:
        # Ignore functions without manually set names
        if len(search_result['name']) == 0:
            continue

        rhs_function = FunctionJsonDeserializer(json.dumps(search_result['data']), config)

        size_ratio = calculate_size_ratio(bl_func.size(), rhs_function.size())
        if size_ratio < size_ratio_threshold:
            continue
        
        comparison = FunctionJsonDeserializer(bl_func.json(),config).compare(rhs_function) 

        if comparison is None:
            continue

        minhash_score = comparison.score.minhash()

        if minhash_score is None or minhash_score < minhash_score_threshold:
            continue
        
        combined_score = (search_result['score'] + minhash_score) / 2.0
        if combined_score < combined_ratio_threshold:
            continue

        data = search_result['data']
        vector_results.append( 
            {
                "id": search_result['id'],
                "name": search_result['name'],
                "timestamp": search_result['timestamp'],
                "username": search_result['username'],
                "sha256": search_result['file_attributes']['sha256'],
                "address": str(data['address']),
                "cyclomatic_complexity": str(data['cyclomatic_complexity']),
                "number_of_instructions": str(data['number_of_instructions']),
                "entropy": str(data['entropy']),
                "average_instructions_per_block": str(data['average_instructions_per_block']),
                "size": str(data['size']),
                "gnn_similarity": str(search_result['score']),
                "minhash_score": str(minhash_score),
                "combined_score": str(combined_score),
                "size_ratio":  str(size_ratio)
            }
        )
    print(vector_results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search for function using GNN vector AND address and SHA256 of the sample", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-f', '--file', required=True, help='Path to the file', default=argparse.SUPPRESS)
    parser.add_argument('-a', '--address', required=True, help='Address of the function', default=argparse.SUPPRESS)
    parser.add_argument('--url', required=True, help='URL of Binlex server', default=argparse.SUPPRESS)
    parser.add_argument('--api', help='API key to access Binlex server', default='39248239c8ed937d6333a41874f1c8e310c5070703af30c06e67b0d308cb82c5')
    parser.add_argument('-db', "--database", help='Database in which the function shall be searched', default='malware')
    
    main(parser.parse_args())
