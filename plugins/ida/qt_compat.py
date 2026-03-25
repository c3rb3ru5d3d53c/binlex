from __future__ import annotations


def import_qt():
    errors: list[str] = []
    for binding in ("PyQt5", "PySide6", "PySide2"):
        try:
            if binding == "PyQt5":
                from PyQt5 import QtCore, QtGui, QtWidgets

                return binding, QtCore, QtGui, QtWidgets
            if binding == "PySide6":
                from PySide6 import QtCore, QtGui, QtWidgets

                return binding, QtCore, QtGui, QtWidgets
            if binding == "PySide2":
                from PySide2 import QtCore, QtGui, QtWidgets

                return binding, QtCore, QtGui, QtWidgets
        except Exception as error:  # noqa: BLE001
            errors.append(f"{binding}: {error}")
    raise RuntimeError("Qt bindings are not available in this IDA Python environment")


def exec_dialog(dialog) -> int:
    exec_method = getattr(dialog, "exec", None)
    if exec_method is not None:
        return int(exec_method())
    return int(dialog.exec_())
