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
import idautils
import ida_kernwin
import ida_ida
import json
import os
from binlex.formats import (
    File,
    PE,
    ELF
)
from binlex.hashing import (
    MinHash32,
    TLSH
)
from binlex import (
    Config,
    Architecture
)
from binlex.controlflow import (
    Graph,
    Instruction,
    FunctionJsonDeserializer,
    BlockJsonDeserializer,
)
from binlex.genetics import Chromosome
from binlex.disassemblers.capstone import Disassembler as CapstoneDisassembler
from binlex.types import MemoryMappedFile
from PyQt5.QtWidgets import QApplication, QDialog
import tempfile
from lib import IDA
from gui.hooks import UIHooks
from gui import (
    register_action_handlers,
    unregister_action_handlers,
    Main,
    SVGWidget,
    Progress,
    JSONSearchWindow,
    OkayCancelDialog,
    About,
)
from lib.text import BANNER
from actions import (
    copy_pattern,
    copy_hex,
    scan_minhash,
    copy_minhash,
    copy_tlsh,
    scan_tlsh,
    function_table,
    search_database,
    index_database,
    export,
    export_byte_colormap,
    copy_block_json,
    copy_block_vector,
    copy_function_vector,
    copy_function_json,
    index_function,
    index_block,
)
from binlex.imaging import ColorMap

class BinlexPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_DRAW
    comment = 'Binlex IDA Plugin'
    help = 'A Binary Genetic Trait Lexer Framework'
    wanted_name = 'Binlex'

    def init(self):
        self.config = Config()
        try:
            self.config.write_default()
        except:
            pass
        self.config.from_default()
        self.main_window = None
        self.about_window = None
        self.function_table_window = None
        self.json_search_window = None
        self.is_disassembled = False
        self.ui_hooks = UIHooks(self)
        self.ui_hooks.hook()
        self.ida = IDA()
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

    def action_index_function(self):
        index_function(self)

    def action_index_block(self):
        index_block(self)

    def _disassemble_controlflow(self):
        number_of_functions = len(IDA.get_functions())
        progress = Progress(title='Disassembling CFG', max_value=number_of_functions)
        progress.show()
        for function in IDA.get_functions():
            progress.increment()
            self.disassemble_function(function)
        progress.close()

    def disassemble_function(self, function):
        for block in IDA.get_function_blocks(function):
            self.disassemble_block(block)

    def disassemble_block(self, block):
        to = set([bb.start_ea for bb in block.succs()])
        for instruction in IDA.get_block_instructions(block):
            self.disassemble_instruction(instruction)
            if IDA().is_function_ea(instruction.ea):
                self.cfg.set_function(instruction.ea)
            if block.start_ea == instruction.ea:
                self.cfg.set_block(instruction.ea)
            if idc.prev_head(block.end_ea) == instruction.ea:
                self.cfg.extend_instruction_edges(instruction.ea, to)

    def disassemble_instruction(self, instruction):
        self.disassembler.disassemble_instruction(instruction.ea, self.cfg)

    def load_disassembler(self):
        self.disassembler = CapstoneDisassembler(self.architecture, self.image, self.executable_address_ranges, self.config)

    def action_copy_block_vector(self):
        copy_block_vector(self)

    def action_copy_block_json(self):
        copy_block_json(self)

    def action_copy_function_vector(self):
        copy_function_vector(self)

    def action_copy_function_json(self):
        copy_function_json(self)

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
        if not self.is_disassembled:
            self._disassemble_controlflow()
            self.is_disassembled = True
            return

        dialog = OkayCancelDialog(title='Disassemble Again?', okay_text='Disassemble', cancel_text='Continue')
        if dialog.exec_() == QDialog.Accepted:
            self._disassemble_controlflow()

    def action_export(self):
        export(self)

    def load_image(self):
        directory = os.path.join(tempfile.gettempdir(), 'binlex')
        if not os.path.exists(directory): os.makedirs(directory)
        file_path = os.path.join(directory, IDA().get_database_sha256())
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
        self.executable_address_ranges = {0: self.mapped_file.size()}
        self.image = self.mapped_file.mmap()

    def load_binary(self) -> bool:
        if ida_ida.inf_get_procname() == 'metapc':
            if ida_ida.inf_is_32bit_exactly() is True:
                self.architecture = Architecture.from_str('i386')
                self.cfg = Graph(self.architecture, self.config)
                self.load_image()
                self.load_disassembler()
                return True
            else:
                self.architecture = Architecture.from_str('amd64')
                self.cfg = Graph(self.architecture, self.config)
                self.load_image()
                self.load_disassembler()
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

    def action_scan_tlsh(self):
        scan_tlsh(self)

    def action_scan_minhash(self):
        scan_minhash(self)

    def action_search_database(self):
        search_database(self)

    def action_json_search_window(self):
        if not self.json_search_window:
            self.disassemble_controlflow()
            data = [json.loads(function.json()) for function in self.cfg.functions()]
            data.extend([json.loads(block.json()) for block in self.cfg.blocks()])
            self.json_search_window = JSONSearchWindow(json_objects=data)
        self.json_search_window.Show('Binlex JSON Search')

    def action_export_byte_colormap(self):
        export_byte_colormap(self)

    def get_function_attributes(self) -> dict:
        results = {}
        for address in self.cfg.queue_functions.valid_addresses():
            attributes = []
            attributes.append(IDA.file_attribute())
            attributes.append(self.get_function_symbol_attribute(address))
            results[address] = attributes
        return results

    def get_block_attributes(self) -> dict:
        results = {}
        for address in self.cfg.queue_blocks.valid_addresses():
            attributes = []
            attributes.append(IDA.file_attribute())
            results[address] = attributes
        return results

    def action_index_database(self):
        index_database(self)

    def action_function_table(self):
        function_table(self)

    def run(self, arg):
        self.open_main_window()

    def term(self):
        self.ui_hooks.unhook()
        unregister_action_handlers()

def PLUGIN_ENTRY():
    return BinlexPlugin()
