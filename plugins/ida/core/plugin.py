from __future__ import annotations

import traceback

import ida_kernwin
import idaapi
import idc

from .compare import apply_match_rows, compare_block, compare_function, compare_functions
from .config import load_plugin_config, save_plugin_config
from .copying import copy_hex, copy_minhash, copy_pattern, copy_tlsh, copy_vector, copy_visual_hash
from .indexing import index_block, index_function, index_functions
from ui.dialogs import CompareDialog, ConfigDialog, IndexDialog, show_error, show_info
from ui.results import ResultsDialog


ACTION_PREFIX = "binlex:mvp:"


class CallbackActionHandler(idaapi.action_handler_t):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def activate(self, ctx):
        self.callback()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class PopupHooks(ida_kernwin.UI_Hooks):
    def __init__(self, controller: "PluginController") -> None:
        super().__init__()
        self.controller = controller

    def finish_populating_widget_popup(self, widget, popup):  # noqa: N802
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type == ida_kernwin.BWN_DISASM:
            self.controller.attach_disasm_popup(widget, popup)
        elif widget_type == ida_kernwin.BWN_PSEUDOCODE:
            self.controller.attach_pseudocode_popup(widget, popup)


class PluginController:
    def __init__(self) -> None:
        self.config = load_plugin_config()
        self.popup_hooks = PopupHooks(self)
        self.registered_actions: list[str] = []
        self.action_handlers = []

    def msg(self, text: str) -> None:
        ida_kernwin.msg(f"[*] {text}\n")

    def run_safe(self, callback) -> None:
        try:
            callback()
        except Exception as error:  # noqa: BLE001
            traceback.print_exc()
            show_error(str(error))

    def register_action(self, suffix: str, label: str, callback) -> None:
        action_name = f"{ACTION_PREFIX}{suffix}"
        handler = CallbackActionHandler(lambda: self.run_safe(callback))
        description = idaapi.action_desc_t(action_name, label, handler)
        ida_kernwin.register_action(description)
        self.registered_actions.append(action_name)
        self.action_handlers.append(handler)

    def register_actions(self) -> None:
        self.register_action("index.functions", "Functions", self.action_index_functions)
        self.register_action("compare.functions", "Functions", self.action_compare_functions)
        self.register_action("config", "Config", self.action_config)

        self.register_action("index.block", "Block", self.action_index_block)
        self.register_action("compare.block", "Block", self.action_compare_block)
        self.register_action("index.function", "Function", self.action_index_function)
        self.register_action("compare.function", "Function", self.action_compare_function)

        self.register_action("copy.vector.block", "Vector", lambda: copy_vector(self.config, False))
        self.register_action("copy.minhash.block", "MinHash", lambda: copy_minhash(self.config, False))
        self.register_action("copy.tlsh.block", "TLSH", lambda: copy_tlsh(self.config, False))
        self.register_action("copy.phash.block", "PHash", lambda: copy_visual_hash(self.config, False, "phash"))
        self.register_action("copy.ahash.block", "AHash", lambda: copy_visual_hash(self.config, False, "ahash"))
        self.register_action("copy.dhash.block", "DHash", lambda: copy_visual_hash(self.config, False, "dhash"))
        self.register_action("copy.hex.block", "Hex", lambda: copy_hex(self.config, False))
        self.register_action("copy.pattern.block", "Pattern", lambda: copy_pattern(self.config, False))

        self.register_action("copy.vector.function", "Vector", lambda: copy_vector(self.config, True))
        self.register_action("copy.minhash.function", "MinHash", lambda: copy_minhash(self.config, True))
        self.register_action("copy.tlsh.function", "TLSH", lambda: copy_tlsh(self.config, True))
        self.register_action("copy.phash.function", "PHash", lambda: copy_visual_hash(self.config, True, "phash"))
        self.register_action("copy.ahash.function", "AHash", lambda: copy_visual_hash(self.config, True, "ahash"))
        self.register_action("copy.dhash.function", "DHash", lambda: copy_visual_hash(self.config, True, "dhash"))
        self.register_action("copy.hex.function", "Hex", lambda: copy_hex(self.config, True))
        self.register_action("copy.pattern.function", "Pattern", lambda: copy_pattern(self.config, True))

    def attach_main_menu(self) -> None:
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/Binlex/Index/Functions",
            f"{ACTION_PREFIX}index.functions",
            ida_kernwin.SETMENU_APP,
        )
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/Binlex/Compare/Functions",
            f"{ACTION_PREFIX}compare.functions",
            ida_kernwin.SETMENU_APP,
        )
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/Binlex/Config",
            f"{ACTION_PREFIX}config",
            ida_kernwin.SETMENU_APP,
        )

    def attach_disasm_popup(self, widget, popup) -> None:
        ida_kernwin.attach_action_to_popup(widget, popup, f"{ACTION_PREFIX}index.block", "Binlex/Index/")
        ida_kernwin.attach_action_to_popup(widget, popup, f"{ACTION_PREFIX}compare.block", "Binlex/Compare/")

        if idaapi.get_func(ida_kernwin.get_screen_ea()) is not None:
            ida_kernwin.attach_action_to_popup(widget, popup, f"{ACTION_PREFIX}index.function", "Binlex/Index/")
            ida_kernwin.attach_action_to_popup(widget, popup, f"{ACTION_PREFIX}compare.function", "Binlex/Compare/")

        for suffix in (
            "copy.vector.block",
            "copy.minhash.block",
            "copy.tlsh.block",
            "copy.phash.block",
            "copy.ahash.block",
            "copy.dhash.block",
            "copy.hex.block",
            "copy.pattern.block",
        ):
            ida_kernwin.attach_action_to_popup(widget, popup, f"{ACTION_PREFIX}{suffix}", "Binlex/Copy/Block/")

        if idaapi.get_func(ida_kernwin.get_screen_ea()) is not None:
            for suffix in (
                "copy.vector.function",
                "copy.minhash.function",
                "copy.tlsh.function",
                "copy.phash.function",
                "copy.ahash.function",
                "copy.dhash.function",
                "copy.hex.function",
                "copy.pattern.function",
            ):
                ida_kernwin.attach_action_to_popup(widget, popup, f"{ACTION_PREFIX}{suffix}", "Binlex/Copy/Function/")

    def attach_pseudocode_popup(self, widget, popup) -> None:
        ida_kernwin.attach_action_to_popup(widget, popup, f"{ACTION_PREFIX}index.function", "Binlex/Index/")
        ida_kernwin.attach_action_to_popup(widget, popup, f"{ACTION_PREFIX}compare.function", "Binlex/Compare/")
        for suffix in (
            "copy.vector.function",
            "copy.minhash.function",
            "copy.tlsh.function",
            "copy.phash.function",
            "copy.ahash.function",
            "copy.dhash.function",
            "copy.pattern.function",
        ):
            ida_kernwin.attach_action_to_popup(widget, popup, f"{ACTION_PREFIX}{suffix}", "Binlex/Copy/")

    def start(self) -> None:
        self.register_actions()
        self.attach_main_menu()
        self.popup_hooks.hook()

    def stop(self) -> None:
        self.popup_hooks.unhook()
        for action_name in self.registered_actions:
            ida_kernwin.unregister_action(action_name)
        self.registered_actions.clear()
        self.action_handlers.clear()

    def available_corpora(self) -> list[str]:
        from .config import build_binlex_config
        from binlex.index import LocalIndex

        config = build_binlex_config(self.config)
        try:
            store = LocalIndex(config, directory=self.config.index_root)
            return store.corpora()
        except Exception:
            return []

    def action_config(self) -> None:
        dialog = ConfigDialog(self.config)
        if dialog.exec_() != dialog.Accepted:
            return
        self.config = dialog.value()
        save_plugin_config(self.config)
        show_info("saved Binlex config")

    def _run_index_dialog(self, title: str, allow_index_blocks: bool):
        dialog = IndexDialog(title, self.config, allow_index_blocks=allow_index_blocks)
        if dialog.exec_() != dialog.Accepted:
            return None
        return dialog.value()

    def action_index_block(self) -> None:
        request = self._run_index_dialog("Binlex Index Block", allow_index_blocks=False)
        if request is None:
            return
        show_info(index_block(self.config, request))

    def action_index_function(self) -> None:
        request = self._run_index_dialog("Binlex Index Function", allow_index_blocks=True)
        if request is None:
            return
        show_info(index_function(self.config, request))

    def action_index_functions(self) -> None:
        request = self._run_index_dialog("Binlex Index Functions", allow_index_blocks=True)
        if request is None:
            return
        show_info(index_functions(self.config, request))

    def _run_compare_dialog(self, title: str):
        dialog = CompareDialog(title, self.config, self.available_corpora())
        if dialog.exec_() != dialog.Accepted:
            return None
        return dialog.value()

    def _show_results(self, title: str, rows: list[dict]) -> None:
        dialog = ResultsDialog(
            title,
            rows,
            apply_one=self._apply_one_row,
            apply_many=self._apply_many_rows,
            jump_local=self._jump_local,
        )
        dialog.exec_()

    def _jump_local(self, row: dict) -> None:
        idc.jumpto(int(row["local_function_address"]))

    def _apply_one_row(self, row: dict) -> None:
        applied, conflicts = apply_match_rows([row])
        if conflicts:
            show_error("\n".join(conflicts))
            return
        show_info(f"applied {applied} name")

    def _apply_many_rows(self, rows: list[dict]) -> None:
        applied, conflicts = apply_match_rows(rows)
        message = f"applied {applied} name(s)"
        if conflicts:
            message += "\n\nSkipped:\n" + "\n".join(conflicts)
        show_info(message)

    def action_compare_block(self) -> None:
        request = self._run_compare_dialog("Binlex Compare Block")
        if request is None:
            return
        self._show_results("Binlex Compare Block", compare_block(self.config, request))

    def action_compare_function(self) -> None:
        request = self._run_compare_dialog("Binlex Compare Function")
        if request is None:
            return
        self._show_results("Binlex Compare Function", compare_function(self.config, request))

    def action_compare_functions(self) -> None:
        request = self._run_compare_dialog("Binlex Compare Functions")
        if request is None:
            return
        self._show_results("Binlex Compare Functions", compare_functions(self.config, request))


class BinlexPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Binlex IDA Plugin"
    help = "Minimal LocalIndex workflow for IDA"
    wanted_name = "Binlex"
    wanted_hotkey = ""

    def init(self):
        self.controller = PluginController()
        self.controller.start()
        ida_kernwin.msg("[*] Binlex plugin loaded\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.controller.run_safe(self.controller.action_config)

    def term(self):
        self.controller.stop()


def PLUGIN_ENTRY():
    return BinlexPlugin()
