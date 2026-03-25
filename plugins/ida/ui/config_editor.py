from __future__ import annotations

from pathlib import Path

import ida_kernwin

from qt_compat import exec_dialog, import_qt


def open_config_editor(path: Path, *, on_save) -> None:
    _, _, _, QtWidgets = import_qt()

    class ConfigEditorDialog(QtWidgets.QDialog):
        def __init__(self) -> None:
            super().__init__(None)
            self.setWindowTitle(f"Binlex Config - {path.name}")
            self.resize(900, 640)

            layout = QtWidgets.QVBoxLayout(self)

            self.editor = QtWidgets.QPlainTextEdit(self)
            self.editor.setPlainText(path.read_text(encoding="utf-8"))
            layout.addWidget(self.editor)

            buttons = QtWidgets.QDialogButtonBox(self)
            save_button = buttons.addButton("Save", QtWidgets.QDialogButtonBox.AcceptRole)
            reload_button = buttons.addButton("Reload", QtWidgets.QDialogButtonBox.ResetRole)
            close_button = buttons.addButton(QtWidgets.QDialogButtonBox.Close)
            layout.addWidget(buttons)

            save_button.clicked.connect(self._save)
            reload_button.clicked.connect(self._reload)
            close_button.clicked.connect(self.reject)

        def _reload(self) -> None:
            self.editor.setPlainText(path.read_text(encoding="utf-8"))

        def _save(self) -> None:
            text = self.editor.toPlainText()
            try:
                path.write_text(text, encoding="utf-8")
                on_save()
            except Exception as error:  # noqa: BLE001
                ida_kernwin.warning(f"Failed to save Binlex config: {error}")
                return
            ida_kernwin.msg(f"[*] saved {path}\n")

    dialog = ConfigEditorDialog()
    exec_dialog(dialog)
