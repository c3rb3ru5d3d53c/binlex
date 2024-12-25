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
from binlex.controlflow import Graph, Instruction, FunctionJsonDeserializer
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
from gui import JSONSearchWindow
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
from binlex.imaging import ColorMap

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
        self.json_search_window = None
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
                j['attributes'].append(self.get_function_symbol_attribute(function.address()))
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

    def action_compare_functions(self):
        dialog = CompareFunctionsDialog()
        if dialog.exec_() != QDialog.Accepted:
            return

        # Retrieve user inputs from the dialog
        (
            minhash_score_threshold,
            mininum_size,
            size_ratio,
            chromosome_minhash_ratio_threshold
        ) = dialog.get_inputs()

        # Prompt the user to select a JSON file
        file_path = ida_kernwin.ask_file(0, "*.json", 'Binlex JSON File')
        if not file_path:
            return

        self.disassemble_controlflow()

        # Build LHS function list (only once)
        lhs_functions = []
        for func in self.cfg.functions():
            lhs_func = FunctionJsonDeserializer(func.json(), self.config)
            # Filter out small functions or those with a low chromosome ratio
            if lhs_func.size() < mininum_size:
                continue
            if lhs_func.chromosome_minhash_ratio() < chromosome_minhash_ratio_threshold:
                continue
            lhs_functions.append(lhs_func)

        # Build RHS function list from JSON file
        rhs_functions = []
        rhs_function_names = {}
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    # Parse JSON exactly once per line
                    try:
                        function_dict = json.loads(line)
                    except json.JSONDecodeError:
                        # Skip lines that aren't valid JSON
                        continue

                    # Skip if not a function
                    if function_dict.get('type') != 'function':
                        continue

                    rhs_func = FunctionJsonDeserializer(line, self.config)

                    # Filter out small functions or those with a low chromosome ratio
                    if rhs_func.size() < mininum_size:
                        continue
                    if rhs_func.chromosome_minhash_ratio() < chromosome_minhash_ratio_threshold:
                        continue

                    rhs_functions.append(rhs_func)
                    # Cache the "RHS function name" only once
                    rhs_function_names[rhs_func.address()] = self.get_rhs_function_name(function_dict)
        except Exception as e:
            ida_kernwin.warning(f"[x] Error reading JSON file: {e}")
            return

        print("[-] starting function compare")
        progress = Progress(title="Comparing Functions", max_value=len(lhs_functions))
        progress.show()

        table = []
        for lhs_function in lhs_functions:
            if progress.is_closed:
                break

            # Precompute common values for LHS
            lhs_address = lhs_function.address()
            lhs_address_hex = hex(lhs_address)
            lhs_contiguous = str(lhs_function.contiguous())
            lhs_name = self.value_to_string(IDA.get_function_name(lhs_address))

            # Filter RHS once based on size ratio
            filtered_rhs = [
                rhs_func for rhs_func in rhs_functions
                if self.size_ratio(lhs_function.size(), rhs_func.size()) >= size_ratio
            ]

            # Compare LHS against the filtered RHS set
            compare_results = lhs_function.compare_many(filtered_rhs)

            for rhs_addr, result in compare_results.items():
                minhash_score = result.score.minhash()
                if minhash_score is None or minhash_score < minhash_score_threshold:
                    continue

                tlsh_score = result.score.tlsh()

                print(f"[-] lhs: {lhs_address_hex} vs. rhs: {hex(rhs_addr)}: {minhash_score}")

                row = [
                    lhs_address_hex,
                    lhs_contiguous,
                    lhs_name,
                    str(hex(rhs_addr)),
                    rhs_function_names[rhs_addr],
                    str(minhash_score),
                    str(self.value_to_string(tlsh_score))
                ]
                table.append(row)

            progress.increment()

        print("[*] function compare completed")
        progress.close()

        headers = [
            "LHS Address",
            "LHS Contiguous",
            "LHS Name",
            "RHS Address",
            "RHS Name",
            "MinHash Score",
            "TLSH Score",
        ]

        form = GradientTable(
            table,
            headers,
            color_column=5,
            min_value=0,
            max_value=1,
            low_to_high=True,
            default_filter_column=2,
            default_sort_column=5,
            default_sort_ascending=False
        )
        form.Show("Binlex Function Compare Table")

    def action_json_search_window(self):
        if not self.json_search_window:
            self.disassemble_controlflow()
            data = [json.loads(function.json()) for function in self.cfg.functions()]
            data.extend([json.loads(block.json()) for block in self.cfg.blocks()])
            self.json_search_window = JSONSearchWindow(json_objects=data)
        self.json_search_window.Show('Binlex JSON Search')

    def action_binary_view(self):
        if not self.binary_view_window:
            colormap = ColorMap()
            segments = []
            for seg_ea in idautils.Segments():
                start = idc.get_segm_start(seg_ea)
                end = idc.get_segm_end(seg_ea)
                segments.append((start, end))
            segments.sort(key=lambda x: x[0], reverse=True)
            for start, end in segments:
                data = IDA.get_bytes(start, end - start)
                colormap.append(start, data)
            SVG_STRING = colormap.to_svg_string()
            self.binary_view_window = SVGWidget(svg_string=SVG_STRING, title='Binlex Color Map')
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
