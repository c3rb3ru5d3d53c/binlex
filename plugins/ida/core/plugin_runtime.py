from __future__ import annotations

import traceback

import ida_kernwin
import idaapi
import idc

from .compare import apply_match_rows, compare_block, compare_function
from .config import ensure_binlex_config_file, load_plugin_config, open_plugin_config_in_editor
from .copying import copy_hex, copy_minhash, copy_pattern, copy_tlsh, copy_vector, copy_visual_hash
from .indexing import index_block, index_function, index_functions
from ui.config_editor import open_config_editor
from ui.dialogs import prompt_compare, prompt_index, show_error, show_info
from ui.launcher import open_launcher
from ui.results import show_results


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
        self.attached_menu_actions: list[tuple[str, str]] = []
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

    def attach_menu_action(self, path: str, suffix: str) -> None:
        action_name = f"{ACTION_PREFIX}{suffix}"
        menu_flag = getattr(ida_kernwin, "SETMENU_APP", getattr(idaapi, "SETMENU_APP", 0))
        ida_kernwin.attach_action_to_menu(path, action_name, menu_flag)
        self.attached_menu_actions.append((path, action_name))

    def register_actions(self) -> None:
        self.register_action("index.functions", "Functions", self.action_index_functions)
        self.register_action("config", "Config", self.action_config)

        self.register_action("index.block", "Block", self.action_index_block)
        self.register_action("compare.block", "Block", self.action_compare_block)
        self.register_action("index.function", "Function", self.action_index_function)
        self.register_action("compare.function", "Function", self.action_compare_function)

        self.register_action("copy.vector.block", "Vector", lambda: copy_vector(self.config, "block"))
        self.register_action("copy.minhash.block", "MinHash", lambda: copy_minhash(self.config, "block"))
        self.register_action("copy.tlsh.block", "TLSH", lambda: copy_tlsh(self.config, "block"))
        self.register_action("copy.phash.block", "PHash", lambda: copy_visual_hash(self.config, "block", "phash"))
        self.register_action("copy.ahash.block", "AHash", lambda: copy_visual_hash(self.config, "block", "ahash"))
        self.register_action("copy.dhash.block", "DHash", lambda: copy_visual_hash(self.config, "block", "dhash"))
        self.register_action("copy.hex.block", "Hex", lambda: copy_hex(self.config, "block"))
        self.register_action("copy.pattern.block", "Pattern", lambda: copy_pattern(self.config, "block"))

        self.register_action("copy.vector.instructions", "Vector", lambda: copy_vector(self.config, "selection"))
        self.register_action("copy.minhash.instructions", "MinHash", lambda: copy_minhash(self.config, "selection"))
        self.register_action("copy.tlsh.instructions", "TLSH", lambda: copy_tlsh(self.config, "selection"))
        self.register_action("copy.phash.instructions", "PHash", lambda: copy_visual_hash(self.config, "selection", "phash"))
        self.register_action("copy.ahash.instructions", "AHash", lambda: copy_visual_hash(self.config, "selection", "ahash"))
        self.register_action("copy.dhash.instructions", "DHash", lambda: copy_visual_hash(self.config, "selection", "dhash"))
        self.register_action("copy.hex.instructions", "Hex", lambda: copy_hex(self.config, "selection"))
        self.register_action("copy.pattern.instructions", "Pattern", lambda: copy_pattern(self.config, "selection"))

        self.register_action("copy.vector.function", "Vector", lambda: copy_vector(self.config, "function"))
        self.register_action("copy.minhash.function", "MinHash", lambda: copy_minhash(self.config, "function"))
        self.register_action("copy.tlsh.function", "TLSH", lambda: copy_tlsh(self.config, "function"))
        self.register_action("copy.phash.function", "PHash", lambda: copy_visual_hash(self.config, "function", "phash"))
        self.register_action("copy.ahash.function", "AHash", lambda: copy_visual_hash(self.config, "function", "ahash"))
        self.register_action("copy.dhash.function", "DHash", lambda: copy_visual_hash(self.config, "function", "dhash"))
        self.register_action("copy.hex.function", "Hex", lambda: copy_hex(self.config, "function"))
        self.register_action("copy.pattern.function", "Pattern", lambda: copy_pattern(self.config, "function"))

    def register_main_menu_actions(self) -> None:
        return None

    def reload_config(self) -> None:
        self.config = load_plugin_config(strict=True)

    def show_launcher(self) -> None:
        commands = [
            ("Binlex -> Config", lambda: self.run_safe(self.action_binlex_config)),
            ("Binlex -> Plugin -> Config", lambda: self.run_safe(self.action_config)),
            ("Binlex -> Index -> Functions", lambda: self.run_safe(self.action_index_functions)),
            ("Binlex -> Compare -> Function", lambda: self.run_safe(self.action_compare_function)),
        ]
        open_launcher(commands)

    def attach_disasm_popup(self, widget, popup) -> None:
        selection = ida_kernwin.read_range_selection(widget)
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

        if selection[0]:
            for suffix in (
                "copy.vector.instructions",
                "copy.minhash.instructions",
                "copy.tlsh.instructions",
                "copy.phash.instructions",
                "copy.ahash.instructions",
                "copy.dhash.instructions",
                "copy.hex.instructions",
                "copy.pattern.instructions",
            ):
                ida_kernwin.attach_action_to_popup(widget, popup, f"{ACTION_PREFIX}{suffix}", "Binlex/Copy/Instructions/")

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
        self.register_main_menu_actions()
        self.popup_hooks.hook()

    def stop(self) -> None:
        self.popup_hooks.unhook()
        detach_action_from_menu = getattr(ida_kernwin, "detach_action_from_menu", None)
        if detach_action_from_menu is not None:
            for path, action_name in self.attached_menu_actions:
                detach_action_from_menu(path, action_name)
        self.attached_menu_actions.clear()
        for action_name in self.registered_actions:
            ida_kernwin.unregister_action(action_name)
        self.registered_actions.clear()
        self.action_handlers.clear()

    def action_config(self) -> None:
        path = open_plugin_config_in_editor(self.config)
        open_config_editor(
            path,
            on_save=self._reload_config_after_save,
        )

    def action_binlex_config(self) -> None:
        path = ensure_binlex_config_file()
        open_config_editor(path, on_save=lambda: None)

    def _reload_config_after_save(self) -> None:
        self.reload_config()
        show_info("reloaded Binlex config")

    def _run_index_dialog(self, title: str, allow_index_blocks: bool):
        self.reload_config()
        return prompt_index(title, self.config, allow_index_blocks=allow_index_blocks)

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
        self.reload_config()
        return prompt_compare(title, self.config)

    def _show_results(self, title: str, rows: list[dict]) -> None:
        show_results(
            title,
            rows,
            apply_one=self._apply_one_row,
            apply_many=self._apply_many_rows,
            jump_local=self._jump_local,
        )

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

class BinlexPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Binlex IDA Plugin"
    help = "Minimal binlex-web workflow for IDA"
    wanted_name = "Binlex"
    wanted_hotkey = ""

    def init(self):
        self.controller = PluginController()
        self.controller.start()
        ida_kernwin.msg("[*] Binlex plugin loaded\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.controller.show_launcher()

    def term(self):
        self.controller.stop()


def create_plugin():
    return BinlexPlugin()
