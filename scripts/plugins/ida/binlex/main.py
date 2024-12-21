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

import idc
import idaapi
import ida_bytes
import ida_segment
import ida_nalt
import idautils
import ida_ua
import ida_kernwin
import ida_loader
import ida_ida
import json
import os
import base64
import zlib
from binlex.formats import File, PE, ELF
from binlex.hashing import MinHash32, TLSH
from binlex import Config, Architecture
from binlex.controlflow import Graph, Instruction
from binlex.genetics import Chromosome
from binlex.disassemblers.capstone import Disassembler as CapstoneDisassembler
from binlex.types import MemoryMappedFile
from PyQt5.QtWidgets import QApplication, QDialog
import tempfile
import os
from assets import LOGO
from assets import MOVIE
from styles import QPUSHBUTTON_STYLE
from text import CREDITS
from ida import IDA
from gui import About
from gui import ScanMinHashInputDialog
from gui.action_handlers import (
    BinlexExportActionHandler,
    CopyMinHashActionHandler,
    CopyPatternActionHandler,
    CopyHexActionHandler,
    ScanMinHashActionHandler,
    ScanTLSHActionHandler,
    CopyTLSHActionHandler,
)
from gui.hooks import UIHooks
from gui import GradientTable
from gui import ScanTLSHInputDialog
from gui import CompareFunctionsDialog
from gui import register_action_handlers
from gui import unregister_action_handlers
from gui import Main
from gui import SVGWidget
from gui import Progress
from text import BANNER
from actions import copy_pattern
from actions import copy_hex
from actions import scan_minhash
from actions import copy_minhash
from actions import copy_tlsh
from actions import scan_tlsh
from actions import function_table
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial

class BinlexPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_DRAW
    comment = 'Binlex IDA Plugin'
    help = 'A Binary Genetic Trait Lexer Framework'
    wanted_name = 'Binlex'

    def init(self):
        self.config = Config()
        self.config.from_default()
        self.main_window = None
        self.about_window = None
        self.table_window = None
        self.binary_view_window = None
        self.ui_hooks = UIHooks(self)
        self.ui_hooks.hook()
        register_action_handlers(self)
        self.load_binary()
        ida_kernwin.msg(BANNER + '\n')
        return idaapi.PLUGIN_KEEP

    def action_copy_pattern(self):
        copy_pattern(self)

    def action_copy_hex(self):
        copy_hex(self)

    def action_copy_tlsh(self):
        copy_tlsh(self)

    def action_copy_minhash(self):
        copy_minhash(self)

    def capstone_disassemble_instruction(self, ea: int, executable_virtual_address_ranges: dict):
        disassembler = CapstoneDisassembler(self.architecture, self.image, executable_virtual_address_ranges, self.config)
        disassembler.disassemble_instruction(ea, self.cfg)

    def disassemble_instruction(self, ea: int, executable_virtual_address_ranges: dict):
        self.capstone_disassemble_instruction(ea, executable_virtual_address_ranges)

    def capstone_disassemble_controlflow(self, architecture: Architecture, image: bytes, executable_address_ranges: dict):
        disassembler = CapstoneDisassembler(architecture, image, executable_address_ranges, self.config)
        number_of_functions = len(IDA.get_functions())
        progress = Progress(title='Disassembling CFG', max_value=number_of_functions)
        progress.show()
        for function in IDA.get_functions():
            progress.increment()
            for block in IDA.get_function_blocks(function):
                for instruction in IDA.get_block_instructions(block):
                    disassembler.disassemble_instruction(instruction.ea, self.cfg)
                    if function.start_ea == instruction.ea:
                        self.cfg.set_function(instruction.ea)
                    if block.start_ea == instruction.ea:
                        self.cfg.set_block(instruction.ea)
        progress.close()

    def update(self, ctx):
        if ctx.widget:
            widget_type = ida_kernwin.get_widget_type(ctx.widget)
            ida_kernwin.msg(f"[*] Widget type: {widget_type}\n")
            if widget_type == ida_kernwin.BWN_DISASM:
                return ida_kernwin.AST_ENABLE_ALWAYS
        return ida_kernwin.AST_DISABLE

    @staticmethod
    def get_function_symbol_attribute(ea: int):
        attribute = {}
        attribute['type'] = 'symbol'
        attribute['symbol_type'] = 'function'
        attribute['file_offset'] = None
        attribute['relative_virtual_address'] = None
        attribute['virtual_address'] = ea
        attribute['name'] = IDA.get_function_name(ea)
        attribute['slice'] = None
        return attribute

    def disassemble_controlflow(self):
        self.capstone_disassemble_controlflow(self.architecture, self.image, {0: self.mapped_file.size()})

    def export(self):
        self.disassemble_controlflow()
        file_path = ida_kernwin.ask_file(1, "*.json", 'Export Binlex Functions to JSON File')
        if not file_path: return
        with open(file_path, 'w') as file:
            for function in self.cfg.functions():
                j = json.loads(function.json())
                j['attributes'] = []
                j['attributes'].append(IDA.file_attribute())
                j['attributes'].append(self.get_function_symbol_attribute(function.address))
                file.write(json.dumps(j) + '\n')
        ida_kernwin.msg(f'[*] exported binlex functions to {file_path}\n')

    def load_image(self):
        directory = os.path.join(tempfile.gettempdir(), 'binlex')
        if not os.path.exists(directory): os.makedirs(directory)
        file_path = os.path.join(directory, ida_nalt.retrieve_input_file_sha256().hex())
        self.mapped_file = MemoryMappedFile(file_path, False)
        for segment in idautils.Segments():
            start = idc.get_segm_start(segment)
            end = idc.get_segm_end(segment)
            data = ida_bytes.get_bytes(start, end - start)
            if data is None: continue
            if self.mapped_file.size() < start:
                self.mapped_file.seek_to_end()
                self.mapped_file.write_padding(start - self.mapped_file.size())
            self.mapped_file.seek_to_end()
            self.mapped_file.write(data)
        self.image = self.mapped_file.as_memoryview()

    def load_binary(self) -> bool:
        if ida_ida.inf_get_procname() == 'metapc':
            if ida_ida.inf_is_32bit_exactly() is True:
                self.architecture = Architecture.from_str('i386')
                self.cfg = Graph(self.architecture, self.config)
                self.load_image()
                return True
            else:
                self.architecture = Architecture.from_str('amd64')
                self.cfg = Graph(self.architecture, self.config)
                self.load_image()
                return True
        return False

    def open_main_window(self):
        if not self.main_window:
            self.main_window = Main(self)
        self.main_window.show()

    def open_about_window(self):
        if not self.about_window:
            self.about_window = About(self)
        self.about_window.exec_()

    @staticmethod
    def value_to_string(value):
        if value is None: return ''
        return value

    def action_scan_tlsh(self):
        scan_tlsh(self)

    def action_scan_minhash(self):
        scan_minhash(self)

    @staticmethod
    def minhash_chromosome_ratio(function: dict) -> float:
        if function['contiguous']: return 1.0
        minhash_size = 0
        for block in function['blocks']:
            if block['chromosome']['minhash'] is not None:
                minhash_size += block['size']
        return minhash_size / function['size']

    @staticmethod
    def size_ratio(len1, len2):
        return 1 - (abs(len1 - len2) / max(len1, len2)) if max(len1, len2) != 0 else 1.0

    @staticmethod
    def get_rhs_function_name(rhs: dict) -> str:
        if rhs['attributes'] is None: return ''
        for attribute in rhs['attributes']:
            if attribute['type'] != 'symbol': continue
            if attribute['symbol_type'] != 'function': continue
            if attribute['name'] is None: continue
            return attribute['name']
        return ''

    @staticmethod
    def compare_function(
        lhs: dict,
        rhs: dict,
        config,
        minhash_score_threshold: float = 0.25,
        chromosome_minhash_ratio_threshold: float = 0.75) -> float | None:
        if lhs['contiguous'] and rhs['contiguous']:
            lhs_chromosome = Chromosome(lhs['chromosome']['pattern'], config)
            rhs_chromosome = Chromosome(rhs['chromosome']['pattern'], config)
            delta = lhs_chromosome.compare(rhs_chromosome)
            if delta is None: return None
            delta = json.loads(delta.json())
            if delta['score']['minhash'] is None: return None
            if delta['score']['minhash'] < minhash_score_threshold: return None
            return delta['score']['minhash']
        lhs_chromosome_minhash_ratio = lhs['chromosome_minhash_ratio']
        rhs_chromosome_minhash_ratio = rhs['chromosome_minhash_ratio']
        if lhs_chromosome_minhash_ratio < chromosome_minhash_ratio_threshold: return None
        if rhs_chromosome_minhash_ratio < chromosome_minhash_ratio_threshold: return None
        minhash_block_scores = []
        for lhs_block in lhs['blocks']:
            lhs_chromosome = Chromosome(lhs_block['chromosome']['pattern'], config)
            minhash_scores = []
            for rhs_block in rhs['blocks']:
                rhs_chromosome = Chromosome(rhs_block['chromosome']['pattern'], config)
                delta = lhs_chromosome.compare(rhs_chromosome)
                if delta is None:
                    minhash_scores.append(0.0)
                    continue
                delta = json.loads(delta.json())
                if delta['score']['minhash'] is None:
                    minhash_scores.append(0.0)
                    continue
                minhash_scores.append(delta['score']['minhash'])
            minhash_score = 0.0
            if len(minhash_scores) > 0:
                minhash_score = max(minhash_scores)
            minhash_block_scores.append(minhash_score)
        minhash_score =  sum(minhash_block_scores) / len(minhash_block_scores)
        if minhash_score < minhash_score_threshold: return None
        return minhash_score

    def action_compare_functions(self):
        dialog = CompareFunctionsDialog()
        if dialog.exec_() != QDialog.Accepted:
            return

        # Retrieve user inputs from the dialog
        minhash_score_threshold, mininum_size, size_ratio, chromosome_minhash_ratio_threshold = dialog.get_inputs()

        # Prompt the user to select a JSON file
        file_path = ida_kernwin.ask_file(0, "*.json", 'Binlex JSON File')
        if not file_path:
            return

        # Disassemble control flow and retrieve all functions from the CFG
        self.disassemble_controlflow()
        all_functions = self.cfg.functions()

        # Pre-filter CFG functions based on size and minhash ratio
        lhs_functions = []
        lhs_names = {}  # Dictionary to store LHS function names
        for func in all_functions:
            func_data = json.loads(func.json())
            if func_data['size'] >= mininum_size and func_data['chromosome_minhash_ratio'] >= chromosome_minhash_ratio_threshold:
                lhs_functions.append(func_data)
                lhs_address = func_data['address']
                # Precompute function names to avoid IDA API calls in threads
                lhs_name = self.value_to_string(IDA.get_function_name(lhs_address))
                lhs_names[lhs_address] = lhs_name

        # Read and parse the JSON file once
        try:
            with open(file_path, 'r') as f:
                rhs_functions_raw = [json.loads(line) for line in f]
        except Exception as e:
            ida_kernwin.warning(f"[x] Error reading JSON file: {e}")
            return

        # Pre-filter RHS functions based on size and minhash ratio
        rhs_functions = []
        rhs_names = {}  # Dictionary to store RHS function names
        for rhs in rhs_functions_raw:
            if rhs['size'] < mininum_size or rhs['chromosome_minhash_ratio'] < chromosome_minhash_ratio_threshold:
                continue
            rhs_functions.append(rhs)
            rhs_address = rhs['address']
            # Precompute function names for RHS
            rhs_name = self.get_rhs_function_name(rhs)
            rhs_names[rhs_address] = rhs_name

        # Initialize and display the progress bar
        progress = Progress(title='Comparing Functions', max_value=len(lhs_functions))
        progress.show()

        table = []
        table_lock = threading.Lock()  # Lock to ensure thread-safe writes to the table

        def worker_compare(lhs, rhs_functions, size_ratio, minhash_score_threshold, chromosome_minhash_ratio_threshold):
            """
            Worker function to compare a single LHS function against all RHS functions.
            Returns a list of rows to be added to the table.
            """
            local_rows = []
            for rhs in rhs_functions:
                # Filter based on size ratio
                ratio = self.size_ratio(lhs['size'], rhs['size'])
                if ratio < size_ratio:
                    continue

                # Perform the comparison using the full JSON objects
                delta = self.compare_function(
                    lhs,
                    rhs,
                    self.config,
                    minhash_score_threshold=minhash_score_threshold,
                    chromosome_minhash_ratio_threshold=chromosome_minhash_ratio_threshold
                )
                if delta is None:
                    continue

                # Retrieve precomputed names
                lhs_address = lhs['address']
                lhs_name = lhs_names.get(lhs_address, 'Unknown')

                rhs_address = rhs['address']
                rhs_name = rhs_names.get(rhs_address, 'Unknown')

                # Retrieve contiguous and minhash fields
                lhs_contiguous = lhs['contiguous']
                lhs_minhash = self.value_to_string(lhs['chromosome']['minhash']) if lhs_contiguous else ''

                rhs_contiguous = rhs['contiguous']
                rhs_minhash = self.value_to_string(rhs['chromosome']['minhash']) if rhs_contiguous else ''

                # Construct the row with all required data
                row = [
                    hex(lhs_address),
                    lhs_name,
                    hex(rhs_address),
                    rhs_name,
                    str(delta),
                    str(lhs_contiguous),
                    str(rhs_contiguous),
                    lhs_minhash,
                    rhs_minhash
                ]
                local_rows.append(row)
            return local_rows

        # Determine the number of worker threads
        max_workers = min(self.config.general.threads, len(lhs_functions))

        # Use ThreadPoolExecutor to manage threads
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Create a partial function with fixed arguments except for 'lhs'
            compare_partial = partial(
                worker_compare,
                rhs_functions=rhs_functions,
                size_ratio=size_ratio,
                minhash_score_threshold=minhash_score_threshold,
                chromosome_minhash_ratio_threshold=chromosome_minhash_ratio_threshold
            )

            # Submit all tasks to the thread pool
            future_to_lhs = {executor.submit(compare_partial, lhs): lhs for lhs in lhs_functions}

            # As each task completes, collect the results and update the table
            for future in as_completed(future_to_lhs):
                lhs = future_to_lhs[future]
                try:
                    rows = future.result()
                    with table_lock:
                        table.extend(rows)
                except Exception as e:
                    ida_kernwin.warning(f"[x] error comparing function at {hex(lhs['address'])}: {e}")
                    return
                finally:
                    # Increment progress by 1 for each completed LHS function
                    progress.increment(1)

        # Close the progress bar after all comparisons are done
        progress.close()

        # Define table headers
        headers = [
            'LHS Address',
            'LHS Name',
            'RHS Address',
            'RHS Name',
            'MinHash Score',
            'LHS Contiguous',
            'RHS Contiguous',
            'LHS MinHash',
            'RHS MinHash'
        ]

        # Create and display the gradient table with the comparison results
        form = GradientTable(
            table,
            headers,
            color_column=4,
            min_value=0,
            max_value=1,
            low_to_high=True,
            default_filter_column=1,
            default_sort_column=4,
            default_sort_ascending=False
        )
        form.Show('Binlex Function Compare Table')


    def action_binary_view(self):
        if not self.binary_view_window:
            SVG_STRING = '''
            <svg xmlns="http://www.w3.org/2000/svg" width="800" height="600">
                <rect x="50" y="50" width="200" height="150" fill="#FF0000" data-json='{"name": "Red Rectangle", "id": 1, "description": "This is a red rectangle."}' />
                <rect x="300" y="50" width="200" height="150" fill="#00FF00" data-json='{"name": "Green Rectangle", "id": 2, "description": "This is a green rectangle."}' />
                <rect x="550" y="50" width="200" height="150" fill="#0000FF" data-json='{"name": "Blue Rectangle", "id": 3, "description": "This is a blue rectangle."}' />
                <rect x="50" y="250" width="200" height="150" fill="#FFFF00" data-json='{"name": "Yellow Rectangle", "id": 4, "description": "This is a yellow rectangle."}' />
                <rect x="300" y="250" width="200" height="150" fill="#FF00FF" data-json='{"name": "Magenta Rectangle", "id": 5, "description": "This is a magenta rectangle."}' />
                <rect x="550" y="250" width="200" height="150" fill="#00FFFF" data-json='{"name": "Cyan Rectangle", "id": 6, "description": "This is a cyan rectangle."}' />
                <!-- Add more rects as needed for testing -->
            </svg>
            '''
            self.binary_view_window = SVGWidget(svg_string=SVG_STRING, title='Binlex Binary View')
        self.binary_view_window.show()

    def open_table_window(self):
        function_table(self)

    def run(self, arg):
        self.open_main_window()

    def term(self):
        self.ui_hooks.unhook()
        unregister_action_handlers()

def PLUGIN_ENTRY():
    return BinlexPlugin()
