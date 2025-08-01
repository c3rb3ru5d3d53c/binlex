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

import ida_kernwin
import idaapi

class BinlexExportActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.export()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class CopyBlockVectorActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_copy_block_vector()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

class CopyMinHashActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_copy_minhash()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

class CopyPatternActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_copy_pattern()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

class CopyBlockJsonActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_copy_block_json()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

class CopyHexActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_copy_hex()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

class ScanMinHashActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_scan_minhash()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

class ScanTLSHActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_scan_tlsh()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

class CopyTLSHActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_copy_tlsh()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

class CopyFunctionVectorActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_copy_function_vector()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

class CopyFunctionJsonActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_copy_function_json()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

class IndexFunctionActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_index_function()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

class IndexBlockActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_index_block()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

def unregister_action_handlers():
    ida_kernwin.unregister_action('binlex:copy_pattern')
    ida_kernwin.unregister_action('binlex:copy_minhash')
    ida_kernwin.unregister_action('binlex:scan_minhash')
    ida_kernwin.unregister_action('binlex:copy_tlsh')
    ida_kernwin.unregister_action('binlex:copy_hex')
    ida_kernwin.unregister_action('binlex::copy_block_vector')
    ida_kernwin.unregister_action('binlex::copy_block_json')
    ida_kernwin.unregister_action('binlex::copy_function_vector')
    ida_kernwin.unregister_action('binlex::copy_function_json')
    ida_kernwin.unregister_action('binlex::index_function')
    ida_kernwin.unregister_action('binlex::index_block')

def register_action_handlers(parent):
    action_desc = idaapi.action_desc_t(
        "binlex:index_block",
        "Index Block",
        IndexBlockActionHandler(parent),
        None,
        "Index current block",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register index_block action.\n')
    action_desc = idaapi.action_desc_t(
        "binlex:index_function",
        "Index Function",
        IndexFunctionActionHandler(parent),
        None,
        "Index current function",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register index_function action.\n')
    action_desc = idaapi.action_desc_t(
        "binlex:copy_function_json",
        "Copy Function JSON",
        CopyFunctionJsonActionHandler(parent),
        None,
        "Copy current function JSON",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register copy_function_json action.\n')
    action_desc = idaapi.action_desc_t(
        "binlex:copy_function_vector",
        "Copy Function Vector",
        CopyFunctionVectorActionHandler(parent),
        None,
        "Copy current function vector",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register copy_function_vector action.\n')
    action_desc = idaapi.action_desc_t(
        "binlex:copy_block_json",
        "Copy Block JSON",
        CopyBlockJsonActionHandler(parent),
        None,
        "Copy current block JSON",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register copy_block_json action.\n')
    action_desc = idaapi.action_desc_t(
        "binlex:copy_block_vector",
        "Copy Block Vector",
        CopyBlockVectorActionHandler(parent),
        None,
        "Copy current block vector",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register copy_block_vector action.\n')
    action_desc = idaapi.action_desc_t(
        "binlex:copy_pattern",
        "Copy Pattern",
        CopyPatternActionHandler(parent),
        None,
        "Copy selected range as pattern",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register copy_pattern action.\n')
    action_desc = idaapi.action_desc_t(
        "binlex:copy_hex",
        "Copy Hex",
        CopyHexActionHandler(parent),
        None,
        "Copy selected range as hex",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register copy_minhash action.\n')
    action_desc = idaapi.action_desc_t(
        "binlex:copy_minhash",
        "Copy MinHash",
        CopyMinHashActionHandler(parent),
        None,
        "Copy selected range as a MinHash",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register copy_minhash action.\n')
    action_desc = idaapi.action_desc_t(
        "binlex:scan_minhash",
        "Scan MinHash",
        ScanMinHashActionHandler(parent),
        None,
        "Scan project for MinHash similarity matches",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register scan_minhash action.\n')
    action_desc = idaapi.action_desc_t(
        "binlex:copy_tlsh",
        "Copy TLSH",
        CopyTLSHActionHandler(parent),
        None,
        "Copy selected range as TLSH",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register copy_tlsh action.\n')
    action_desc = idaapi.action_desc_t(
        "binlex:scan_tlsh",
        "Scan TLSH",
        ScanTLSHActionHandler(parent),
        None,
        "Scan project for TLSH similarity matches",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register scan_tlsh action.\n')
