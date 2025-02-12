#!/usr/bin/env python
#                    GNU LESSER GENERAL PUBLIC LICENSE
#                        Version 3, 29 June 2007
#
#  Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
#  Everyone is permitted to copy and distribute verbatim copies
#  of this license document, but changing it is not allowed.
#
#
#   This version of the GNU Lesser General Public License incorporates
# the terms and conditions of version 3 of the GNU General Public
# License, supplemented by the additional permissions listed below.
#
#   0. Additional Definitions.
#
#   As used herein, "this License" refers to version 3 of the GNU Lesser
# General Public License, and the "GNU GPL" refers to version 3 of the GNU
# General Public License.
#
#   "The Library" refers to a covered work governed by this License,
# other than an Application or a Combined Work as defined below.
#
#   An "Application" is any work that makes use of an interface provided
# by the Library, but which is not otherwise based on the Library.
# Defining a subclass of a class defined by the Library is deemed a mode
# of using an interface provided by the Library.
#
#   A "Combined Work" is a work produced by combining or linking an
# Application with the Library.  The particular version of the Library
# with which the Combined Work was made is also called the "Linked
# Version".
#
#   The "Minimal Corresponding Source" for a Combined Work means the
# Corresponding Source for the Combined Work, excluding any source code
# for portions of the Combined Work that, considered in isolation, are
# based on the Application, and not on the Linked Version.
#
#   The "Corresponding Application Code" for a Combined Work means the
# object code and/or source code for the Application, including any data
# and utility programs needed for reproducing the Combined Work from the
# Application, but excluding the System Libraries of the Combined Work.
#
#   1. Exception to Section 3 of the GNU GPL.
#
#   You may convey a covered work under sections 3 and 4 of this License
# without being bound by section 3 of the GNU GPL.
#
#   2. Conveying Modified Versions.
#
#   If you modify a copy of the Library, and, in your modifications, a
# facility refers to a function or data to be supplied by an Application
# that uses the facility (other than as an argument passed when the
# facility is invoked), then you may convey a copy of the modified
# version:
#
#    a) under this License, provided that you make a good faith effort to
#    ensure that, in the event an Application does not supply the
#    function or data, the facility still operates, and performs
#    whatever part of its purpose remains meaningful, or
#
#    b) under the GNU GPL, with none of the additional permissions of
#    this License applicable to that copy.
#
#   3. Object Code Incorporating Material from Library Header Files.
#
#   The object code form of an Application may incorporate material from
# a header file that is part of the Library.  You may convey such object
# code under terms of your choice, provided that, if the incorporated
# material is not limited to numerical parameters, data structure
# layouts and accessors, or small macros, inline functions and templates
# (ten or fewer lines in length), you do both of the following:
#
#    a) Give prominent notice with each copy of the object code that the
#    Library is used in it and that the Library and its use are
#    covered by this License.
#
#    b) Accompany the object code with a copy of the GNU GPL and this license
#    document.
#
#   4. Combined Works.
#
#   You may convey a Combined Work under terms of your choice that,
# taken together, effectively do not restrict modification of the
# portions of the Library contained in the Combined Work and reverse
# engineering for debugging such modifications, if you also do each of
# the following:
#
#    a) Give prominent notice with each copy of the Combined Work that
#    the Library is used in it and that the Library and its use are
#    covered by this License.
#
#    b) Accompany the Combined Work with a copy of the GNU GPL and this license
#    document.
#
#    c) For a Combined Work that displays copyright notices during
#    execution, include the copyright notice for the Library among
#    these notices, as well as a reference directing the user to the
#    copies of the GNU GPL and this license document.
#
#    d) Do one of the following:
#
#        0) Convey the Minimal Corresponding Source under the terms of this
#        License, and the Corresponding Application Code in a form
#        suitable for, and under terms that permit, the user to
#        recombine or relink the Application with a modified version of
#        the Linked Version to produce a modified Combined Work, in the
#        manner specified by section 6 of the GNU GPL for conveying
#        Corresponding Source.
#
#        1) Use a suitable shared library mechanism for linking with the
#        Library.  A suitable mechanism is one that (a) uses at run time
#        a copy of the Library already present on the user's computer
#        system, and (b) will operate properly with a modified version
#        of the Library that is interface-compatible with the Linked
#        Version.
#
#    e) Provide Installation Information, but only if you would otherwise
#    be required to provide such information under section 6 of the
#    GNU GPL, and only to the extent that such information is
#    necessary to install and execute a modified version of the
#    Combined Work produced by recombining or relinking the
#    Application with a modified version of the Linked Version. (If
#    you use option 4d0, the Installation Information must accompany
#    the Minimal Corresponding Source and Corresponding Application
#    Code. If you use option 4d1, you must provide the Installation
#    Information in the manner specified by section 6 of the GNU GPL
#    for conveying Corresponding Source.)
#
#   5. Combined Libraries.
#
#   You may place library facilities that are a work based on the
# Library side by side in a single library together with other library
# facilities that are not Applications and are not covered by this
# License, and convey such a combined library under terms of your
# choice, if you do both of the following:
#
#    a) Accompany the combined library with a copy of the same work based
#    on the Library, uncombined with any other library facilities,
#    conveyed under the terms of this License.
#
#    b) Give prominent notice with the combined library that part of it
#    is a work based on the Library, and explaining where to find the
#    accompanying uncombined form of the same work.
#
#   6. Revised Versions of the GNU Lesser General Public License.
#
#   The Free Software Foundation may publish revised and/or new versions
# of the GNU Lesser General Public License from time to time. Such new
# versions will be similar in spirit to the present version, but may
# differ in detail to address new problems or concerns.
#
#   Each version is given a distinguishing version number. If the
# Library as you received it specifies that a certain numbered version
# of the GNU Lesser General Public License "or any later version"
# applies to it, you have the option of following the terms and
# conditions either of that published version or of any later version
# published by the Free Software Foundation. If the Library as you
# received it does not specify a version number of the GNU Lesser
# General Public License, you may choose any version of the GNU Lesser
# General Public License ever published by the Free Software Foundation.
#
#   If the Library as you received it specifies that a proxy can decide
# whether future versions of the GNU Lesser General Public License shall
# apply, that proxy's public statement of acceptance of any version is
# permanent authorization for you to choose that version for the
# Library.

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