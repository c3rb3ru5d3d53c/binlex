#!/usr/bin/env python

import json
import sys
import os


def noramilize_binlex_data(binlex_flat_file):
    # Parse binlex data into three sets
    # function_set - set of function addresses
    # bb_set - set of bb addresses
    # bb_code_map - dict of basic block bytes
    function_set = set()
    bb_set = set()
    bb_code_map = {}
    with open(binlex_flat_file,'r') as fp:
        for line in fp.read().split('\n'):
            if line != '':
                trait_data = json.loads(line)
                trait_type = trait_data.get('type')
                trait_offset = trait_data.get('offset')
                if trait_type == "function":
                    function_set.add(trait_offset)
                elif trait_type == "block":
                    bb_set.add(trait_offset)
                    bb_code_map[trait_offset] = trait_data.get('bytes')
    return function_set, bb_set, bb_code_map


def normalize_ida_data(ida_json_file):
    # Parse ida data into three sets
    # function_set - set of function addresses
    # bb_set - set of bb addresses
    # bb_code_map - dict of basic block bytes
    function_set = set()
    bb_set = set()
    bb_code_map = {}
    ida_data = json.loads(open(ida_json_file,'r').read())
    for trait_data in ida_data:
        trait_type = trait_data.get('type')
        trait_offset = trait_data.get('offset')
        if trait_type == "function":
            function_set.add(trait_offset)
        elif trait_type == "block":
            bb_set.add(trait_offset)
            bb_code_map[trait_offset] = trait_data.get('bytes')
    return function_set, bb_set, bb_code_map


def calculate_coverage(ida_json_file, binlex_flat_file):
    binlex_function_set, binlex_bb_set, binlex_bb_code_map = noramilize_binlex_data(binlex_flat_file)
    ida_function_set, ida_bb_set, ida_bb_code_map = normalize_ida_data(ida_json_file)

    total_missing_functions = len(ida_function_set.difference(binlex_function_set))
    total_functions = len(ida_function_set)
    function_coverage = round((total_functions - total_missing_functions)/total_functions* 100,2)

    intersection_bb = ida_bb_set.intersection(binlex_bb_set)
    total_bb = len(ida_bb_set)
    total_missing_bb = total_bb - len(intersection_bb)
    bb_coverage = round((total_bb - total_missing_bb)/total_bb* 100,2)
    total_extra_bb = len(binlex_bb_set) - len(intersection_bb)

    total_missmatch_bb = 0

    for bb in intersection_bb:
        if binlex_bb_code_map[bb] != ida_bb_code_map[bb]:
            total_missmatch_bb += 1

    return {'total_missing_functions':total_missing_functions, 
            'total_functions':total_functions,
            'function_coverage':function_coverage,
            'total_missing_bb':total_missing_bb,
            'total_bb':total_bb,
            'bb_coverage':bb_coverage,
            'total_missmatch_bb':total_missmatch_bb,
            'extra_bb':total_extra_bb
            }


def main():
    if len(sys.argv) != 3:
        print(f"\nArgument Error! - Please feed me exactly: \n\n\t{sys.argv[0]} <path_to_ida_json_file> <path_to_binlex_flat_file>\n")
        sys.exit(1)

    coverage = calculate_coverage(sys.argv[1], sys.argv[2])

    print(f"Function coverage: {coverage.get('function_coverage')}%  ( Missing {coverage.get('total_missing_functions')} from total {coverage.get('total_functions')} )")
    print(f"Basic block coverage: {coverage.get('bb_coverage')}%  ( Missing {coverage.get('total_missing_bb')} from total {coverage.get('total_bb')} )")
    print(f"Basic block errors: {coverage.get('total_missmatch_bb')}")
    print(f"Extra blocks from binlex: {coverage.get('extra_bb')}")




if __name__ == "__main__":
    main()









