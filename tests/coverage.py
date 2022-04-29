#!/usr/bin/env python

import json
import sys
import os


def calculate_coverage(ida_json_file, binlex_flat_file):
    ida_data = json.loads(open(ida_json_file,'r').read())

    binlex_data = []

    with open(binlex_flat_file,'r') as fp:
        for line in fp.read().split('\n'):
            if line != '':
                binlex_data.append(json.loads(line))


    missing_functions = []
    total_functions = []
    missing_bb = []
    total_bb = []
    missmatch_bb = []


    for ida_trait in ida_data:
        ida_trait_offset = ida_trait.get('offset')
        ida_trait_type = ida_trait.get('type')
        matched = False


        for binlex_trait in binlex_data:
            binlex_trait_offset = binlex_trait.get('offset')
            binlex_trait_type = binlex_trait.get('type')

            if ida_trait_offset == binlex_trait_offset and ida_trait_type == binlex_trait_type:
                matched = True
                if ida_trait_type == "function":
                    continue
                
                # Test if the basic block matches 
                ida_trait_bytes = ida_trait.get('bytes')
                binlex_trait_bytes = binlex_trait.get('bytes')
                if ida_trait_bytes != binlex_trait_bytes:
                    missmatch_bb.append(ida_trait_offset)

        # If there was no match record it
        if ida_trait_type == "function":
            total_functions.append(ida_trait_offset)
            if not matched:
                missing_functions.append(ida_trait_offset)
        else:
            total_bb.append(ida_trait_offset)
            if not matched:
                missing_bb.append(ida_trait_offset)
            

    total_missing_functions = len(missing_functions)
    total_functions = len(total_functions)
    function_coverage = round((total_functions - total_missing_functions)/total_functions* 100,2)

    total_missing_bb = len(missing_bb)
    total_bb = len(total_bb)
    bb_coverage = round((total_bb - total_missing_bb)/total_bb* 100,2)

    total_missmatch_bb = len(missmatch_bb)

    return {'total_missing_functions':total_missing_functions, 
            'total_functions':total_functions,
            'function_coverage':function_coverage,
            'total_missing_bb':total_missing_bb,
            'total_bb':total_bb,
            'bb_coverage':bb_coverage,
            'total_missmatch_bb':total_missmatch_bb
            }


def main():
    if len(sys.argv) != 3:
        print(f"\nArgument Error! - Please feed me exactly: \n\n\t{sys.argv[0]} <path_to_ida_json_file> <path_to_binlex_flat_file>\n")
        sys.exit(1)

    #ida_json_file = '/private/tmp/pe/pe.emotet.x86.ida.json'
    #binlex_flat_file = '/private/tmp/emotet.binlex.json'

    coverage = calculate_coverage(sys.argv[1], sys.argv[2])

    print(f"Function coverage: {coverage.get('function_coverage')}%  ( Missing {coverage.get('total_missing_functions')} from total {coverage.get('total_functions')} )")
    print(f"Basic block coverage: {coverage.get('bb_coverage')}%  ( Missing {coverage.get('total_missing_bb')} from total {coverage.get('total_bb')} )")
    print(f"Basic block errors: {coverage.get('total_missmatch_bb')}")




if __name__ == "__main__":
    main()









