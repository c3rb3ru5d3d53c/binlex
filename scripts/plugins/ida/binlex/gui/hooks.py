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

import idaapi
import ida_kernwin

class UIHooks(idaapi.UI_Hooks):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def finish_populating_widget_popup(self, widget, popup):
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                "binlex:copy_pattern",
                "Binlex/"
            )
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                "binlex:copy_hex",
                "Binlex/"
            )
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                "binlex:copy_minhash",
                "Binlex/"
            )
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                "binlex:copy_tlsh",
                "Binlex/"
            )
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                "binlex:scan_minhash",
                "Binlex/"
            )
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                "binlex:scan_tlsh",
                "Binlex/"
            )
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                "binlex:copy_block_vector",
                "Binlex/"
            )
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                "binlex:copy_block_json",
                "Binlex/"
            )
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                "binlex:copy_function_vector",
                "Binlex/"
            )
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                "binlex:copy_function_json",
                "Binlex/"
            )
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                "binlex:index_function",
                "Binlex/"
            )
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                "binlex:index_block",
                "Binlex/"
            )
