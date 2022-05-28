#!/usr/bin/env python

import os
import sys
import json
import zipfile
import subprocess

zip_files = [
    'tests/pe.zip',
    'tests/raw.zip',
    'tests/elf.zip'
]

pe_files = [
    'tests/pe/pe.cil.0',
    'tests/pe/pe.cil.1',
    'tests/pe/emotet.x86',
    'tests/pe/pe.trickbot.x86',
    'tests/pe/pe.trickbot.x86_64',
    'tests/pe/pe.x86',
    'tests/pe/pe.x86_64'
]

elf_files = [
    'tests/elf/elf.x86',
    'tests/elf/elf.x86_64'
]

coverage_files = [
    {
        'ida': 'tests/ida_baseline/elf.x86.ida.json',
        'binlex': 'tests/elf/elf.x86.json'
    },
    {
        'ida': 'tests/ida_baseline/elf.x86_64.ida.json',
        'binlex': 'tests/elf/elf.x86_64.json'
    },
    {
        'ida': 'tests/ida_baseline/pe.trickbot.x86.ida.json',
        'binlex': 'tests/pe/pe.trickbot.x86.json'
    },
    {
        'ida': 'tests/ida_baseline/pe.trickbot.x86_64.ida.json',
        'binlex': 'tests/pe/pe.trickbot.x86_64.json'
    },
    {
        'ida': 'tests/ida_baseline/pe.x86.ida.json',
        'binlex': 'tests/pe/pe.x86.json'
    },
    {
        'ida': 'tests/ida_baseline/pe.x86_64.ida.json',
        'binlex': 'tests/pe/pe.x86_64.json'
    }
]

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

def print_coverage(coverage):
    print(f"Function coverage: {coverage.get('function_coverage')}%  ( Missing {coverage.get('total_missing_functions')} from total {coverage.get('total_functions')} )")
    print(f"Basic block coverage: {coverage.get('bb_coverage')}%  ( Missing {coverage.get('total_missing_bb')} from total {coverage.get('total_bb')} )")
    print(f"Basic block errors: {coverage.get('total_missmatch_bb')}")
    print(f"Extra blocks from binlex: {coverage.get('extra_bb')}")

for zip_file in zip_files:
    print("[-] {}".format(zip_file))
    z = zipfile.ZipFile(zip_file,"r")
    z.setpassword(b'infected')
    z.extractall("tests/")
    print("[*] {}".format(zip_file))

for pe_file in pe_files:
    print("[-] {}".format(pe_file))
    command = [
        'build/binlex',
        '-i', pe_file,
        '-o', os.path.join(os.path.dirname(pe_file),os.path.basename(pe_file) + '.json')]
    subprocess.run(command)
    print("[*] {}".format(pe_file))

for elf_file in elf_files:
    print("[-] {}".format(elf_file))
    command = [
        'build/binlex',
        '-i', elf_file,
        '-o', os.path.join(os.path.dirname(elf_file),os.path.basename(elf_file) + '.json')]
    subprocess.run(command)
    print("[*] {}".format(elf_file))

for coverage_file in coverage_files:
    print_coverage(calculate_coverage(coverage_file['ida'], coverage_file['binlex']))
