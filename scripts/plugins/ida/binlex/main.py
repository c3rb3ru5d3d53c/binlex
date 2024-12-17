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
import json
import os
import base64
import zlib
from binlex.formats import File, PE, ELF
from binlex.hashing import MinHash32, TLSH
from binlex import Config, Architecture
from binlex.controlflow import Graph, Instruction
from binlex.disassemblers.capstone import Disassembler as CapstoneDisassembler
from PyQt5.QtWidgets import QApplication, QDialog

from assets import LOGO
from assets import MOVIE
from styles import QPUSHBUTTON_STYLE
from text import CREDITS
from ida import IDA
from gui.about import About
from gui.scan_minhash import ScanMinHashInputDialog
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
from gui.gradient_table import GradientTable
from gui.scan_tlsh import ScanTLSHInputDialog
from gui.action_handlers import register_action_handlers
from gui.main import Main
from text import BANNER

class BinlexPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_DRAW
    comment = "Binlex IDA Plugin"
    help = "A Binary Genetic Trait Lexer Framework"
    wanted_name = "Binlex"

    def init(self):
        self.config = Config()
        self.main_window = None
        self.about_window = None
        self.table_window = None
        self.ui_hooks = UIHooks(self)
        self.ui_hooks.hook()
        register_action_handlers(self)
        self.load_image()
        ida_kernwin.msg(BANNER + '\n')
        return idaapi.PLUGIN_KEEP

    def action_copy_pattern(self):
        start_ea, end_ea = IDA.get_disassembly_selection_range()
        pattern = ''
        pc = start_ea
        while pc < end_ea:
            insn = ida_ua.insn_t()
            ida_ua.decode_insn(insn, pc)
            self.disassemble_instruction(pc, {start_ea: end_ea})
            blinsn = Instruction(pc, self.cfg)
            pattern += blinsn.chromosome().pattern()
            pc += insn.size
        QApplication.clipboard().setText(pattern)
        ida_kernwin.msg('[*] pattern copied to clipboard\n')

    def action_copy_hex(self):
        start_ea, end_ea = IDA.get_disassembly_selection_range()
        pattern = ida_bytes.get_bytes(start_ea, end_ea - start_ea).hex()
        QApplication.clipboard().setText(pattern)
        ida_kernwin.msg('[*] hex copied to clipboard\n')

    def action_copy_tlsh(self):
        start_ea, end_ea = IDA.get_disassembly_selection_range()
        data = ida_bytes.get_bytes(start_ea, end_ea - start_ea)
        tlsh = TLSH(data).hexdigest(50)
        if tlsh is None:
            ida_kernwin.msg('[x] not enough data or minhash failed\n')
            return
        QApplication.clipboard().setText(tlsh)
        ida_kernwin.msg(f'[*] copied tlsh to clipboard based on {len(data)} bytes\n')

    def action_copy_minhash(self):
        start_ea, end_ea = IDA.get_disassembly_selection_range()
        data = ida_bytes.get_bytes(start_ea, end_ea - start_ea)
        minhash = MinHash32(
            data,
            self.config.instructions.hashing.minhash.number_of_hashes,
            self.config.instructions.hashing.minhash.shingle_size,
            self.config.instructions.hashing.minhash.seed).hexdigest()
        if minhash is None:
            ida_kernwin.msg('[x] not enough data or minhash failed\n')
            return
        QApplication.clipboard().setText(minhash)
        ida_kernwin.msg(f'[*] copied minhash to clipboard based on {len(data)} bytes\n')

    def capstone_disassemble_instruction(self, ea: int, executable_virtual_address_ranges: dict):
        disassembler = CapstoneDisassembler(self.architecture, self.image, executable_virtual_address_ranges)
        disassembler.disassemble_instruction(ea, self.cfg)

    def disassemble_instruction(self, ea: int, executable_virtual_address_ranges: dict):
        self.capstone_disassemble_instruction(ea, executable_virtual_address_ranges)

    def capstone_disassemble_controlflow(self, architecture: Architecture, image: bytes, executable_address_ranges: dict):
        disassembler = CapstoneDisassembler(architecture, image, executable_address_ranges)
        for function in IDA.get_functions():
            for block in IDA.get_function_blocks(function):
                for instruction in IDA.get_block_instructions(block):
                    disassembler.disassemble_instruction(instruction.ea, self.cfg)
                    if function.start_ea == instruction.ea:
                        self.cfg.set_function(instruction.ea)
                    if block.start_ea == instruction.ea:
                        self.cfg.set_block(instruction.ea)

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
        self.capstone_disassemble_controlflow(self.architecture, self.image, self.executable_virtual_address_ranges)

    def export(self):
        self.disassemble_controlflow()
        file_path = ida_kernwin.ask_file(1, "*.json", 'Export Binlex Functions to JSON File')
        if not file_path: return
        with open(file_path, 'w') as file:
            for function in self.cfg.functions():
                j = json.loads(function.json())
                j['attributes'] = []
                j['attributes'].append(self.file_attribute)
                j['attributes'].append(self.get_function_symbol_attribute(function.address))
                file.write(json.dumps(j) + '\n')
        ida_kernwin.msg(f'[*] exported binlex functions to {file_path}\n')

    def load_pe(self):
        pe = PE(idc.get_input_file_path(), self.config)
        self.architecture = pe.architecture()
        self.file_attribute = json.loads(pe.file_json())
        self.cfg = Graph(self.architecture, self.config)
        self.mapped_file = pe.image()
        self.image = self.mapped_file.as_memoryview()
        self.executable_virtual_address_ranges = pe.executable_virtual_address_ranges()

    def load_elf(self):
        elf = ELF(idc.get_input_file_path(), self.config)
        self.architecture = pe.architecture()
        self.file_attribute = json.loads(elf.file_json())
        self.cfg = Graph(self.architecture, self.config)
        self.mapped_file = elf.image()
        self.image = self.mapped_file.as_memoryview()
        self.executable_virtual_address_ranges = elf.executable_virtual_address_ranges()

    def load_image(self) -> bool:
        file_type = ida_loader.get_file_type_name()
        if '(PE)' in file_type:
            self.load_pe()
            return True
        if '(ELF)' in file_type:
            self.load_elf()
            return True
        return False

    def open_main_window(self):
        if not self.main_window:
            self.main_window = Main(self)
        self.main_window.exec_()

    def open_about_window(self):
        if not self.about_window:
            self.about_window = About(self)
        self.about_window.exec_()

    @staticmethod
    def value_to_string(value):
        if value is None: return ''
        return value

    def action_scan_tlsh(self):
        dialog = ScanTLSHInputDialog()
        if dialog.exec_() != QDialog.Accepted: return
        rhs_tlsh, num_bytes, threshold = dialog.get_inputs()
        table = []
        for addr in IDA.get_instruction_addresses():
            data = idaapi.get_bytes(addr, num_bytes)
            lhs_tlsh = TLSH(data).hexdigest(50)
            if lhs_tlsh is None: continue
            similarity = TLSH.compare(lhs_tlsh, rhs_tlsh)
            if similarity is not None and similarity < threshold:
                row = []
                row.append(str(hex(addr)))
                row.append(self.value_to_string(similarity))
                row.append(rhs_tlsh)
                row.append(lhs_tlsh)
                table.append(row)
        headers = [
            'Address',
            'Score',
            'TLSH LHS',
            'TLSH RHS',
        ]
        form = GradientTable(
            table,
            headers,
            color_column=1,
            min_value=threshold,
            max_value=0,
            low_to_high=True,
            default_filter_column=0,
            default_sort_column=1,
            default_sort_ascending=True)
        form.Show('Binlex TLSH Scan Table')

    def action_scan_minhash(self):
        dialog = ScanMinHashInputDialog()
        if dialog.exec_() != QDialog.Accepted: return
        rhs_minhash, num_bytes, threshold = dialog.get_inputs()
        table = []
        for addr in IDA.get_instruction_addresses():
            data = idaapi.get_bytes(addr, num_bytes)
            lhs_minhash = MinHash32(
                data,
                self.config.instructions.hashing.minhash.number_of_hashes,
                self.config.instructions.hashing.minhash.shingle_size,
                self.config.instructions.hashing.minhash.seed).hexdigest()
            similarity = MinHash32.compare_jaccard_similarity(lhs_minhash, rhs_minhash)
            if similarity is not None and similarity > threshold:
                row = []
                row.append(str(hex(addr)))
                row.append(self.value_to_string(similarity))
                row.append(lhs_minhash)
                row.append(rhs_minhash)
                table.append(row)
        headers = [
            'Address',
            'Score',
            'MinHash LHS',
            'MinHash RHS',
        ]
        form = GradientTable(
            table,
            headers,
            color_column=1,
            min_value=threshold,
            max_value=1,
            low_to_high=True,
            default_filter_column=0,
            default_sort_column=1,
            default_sort_ascending=False)
        form.Show('Binlex MinHash Scan Table')

    @staticmethod
    def minhash_chromosome_ratio(function: dict) -> float:
        if function['contiguous']: return 1.0
        minhash_size = 0
        for block in function['blocks']:
            if block['chromosome']['minhash'] is not None:
                minhash_size += block['size']
        return minhash_size / function['size']

    @staticmethod
    def compare_function(lhs: str, rhs: str) -> dict | None:
        similarity = {
            'minhash': None,
            'tlsh': None,
        }
        lhs = json.loads(lhs)
        rhs = json.loads(rhs)
        if lhs['contiguous'] and rhs['contiguous']:
            lhs_chromosome = lhs['chromosome']
            rhs_chromosome = rhs['chromosome']
            if lhs_chromosome is None and rhs_chromosome is None:
                return None
            lhs_chromosome_minhash = lhs['chromosome']['minhash']
            rhs_chromosome_minhash = rhs['chromosome']['minhash']
            if lhs_chromosome_minhash is not None and rhs_chromosome_minhash is not None:
                similarity['minhash'] = MinHash32.compare_jaccard_similarity(lhs_chromosome_minhash, rhs_chromosome_minhash)
            return similarity
        lhs_minhash_chromosome_ratio = self.minhash_chromosome_ratio(lhs)
        rhs_minhash_chromosome_ratio = self.minhash_chromosome_ratio(rhs)
        if lhs_minhash_chromosome_ratio < 0.75 and rhs_minhash_chromosome_ratio < 0.75:
            return None
        minhash_values = []
        for lhs_block in lhs['blocks']:
            best_minhash = None
            lhs_block_chromosome_minhash = lhs_block['chromosome']['minhash']
            for rhs_block in rhs['blocks']:
                rhs_block_chromosome_minhash = rhs_block['chromosome']['minhash']
                similarity_value = MinHash32.compare_jaccard_similarity(lhs_block_chromosome_minhash, rhs_block_chromosome_minhash)
                if best_minhash is None or (similarity_value is not None and similarity_value > best_minhash):
                    best_minhash = similarity_value
            if best_minhash is not None:
                minhash_values.append(best_minhash)
        if not minhash_values:
            return None
        similarity['minhash'] = sum(minhash_values) / len(minhash_values)
        return similarity

    def open_table_window(self):
        if self.table_window: return None
        self.disassemble_controlflow()
        data = []
        for function in self.cfg.functions():
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
            row.append(self.value_to_string(function.minhash_chromosome_ratio()))
            if chromosome is not None:
                row.append(self.value_to_string(chromosome.minhash()))
            else:
                row.append(self.value_to_string(None))
            row.append(self.value_to_string(function.tlsh_chromosome_ratio()))
            if chromosome is not None:
                row.append(self.value_to_string(chromosome.tlsh()))
            else:
                row.append(self.value_to_string(None))
            if chromosome is not None:
                row.append(self.value_to_string(function.chromosome().pattern()))
            else:
                row.append(self.value_to_string(None))
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

    def run(self, arg):
        self.open_main_window()

    def term(self):
        self.ui_hooks.unhook()
        ida_kernwin.unregister_action("binlex:copy_pattern")
        ida_kernwin.unregister_action("binlex:copy_minhash")
        ida_kernwin.unregister_action("binlex:scan_minhash")
        ida_kernwin.unregister_action("binlex:copy_tlsh")
        ida_kernwin.unregister_action("binlex:copy_hex")

def PLUGIN_ENTRY():
    return BinlexPlugin()
