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
