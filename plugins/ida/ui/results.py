from __future__ import annotations

import ida_kernwin

try:
    from qt_compat import exec_dialog, import_qt
except ModuleNotFoundError:  # pragma: no cover - fallback for packaged package layouts
    from ..qt_compat import exec_dialog, import_qt


def _format_row(index: int, row: dict) -> str:
    return (
        f"[{index}] "
        f"local={hex(int(row['local_address']))} "
        f"name='{row['local_name']}' "
        f"score={float(row['score']):.6f} "
        f"match={hex(int(row['match_address']))} "
        f"match_name='{row['match_name']}' "
        f"corpus='{row['corpus']}' "
        f"sha256={row['sha256']}"
    )


def _copy_rows_to_clipboard(rows: list[dict]) -> bool:
    try:
        _, _, QtGui, _ = import_qt()
    except Exception:
        return False

    header = [
        "Local Name",
        "Local Address",
        "Match Name",
        "Match Address",
        "Score",
        "Corpus",
        "SHA256",
    ]
    lines = ["\t".join(header)]
    for row in rows:
        lines.append(
            "\t".join(
                [
                    str(row["local_name"]),
                    hex(int(row["local_address"])),
                    str(row["match_name"]),
                    hex(int(row["match_address"])),
                    f"{float(row['score']):.6f}",
                    str(row["corpus"]),
                    str(row["sha256"]),
                ]
            )
        )
    QtGui.QGuiApplication.clipboard().setText("\n".join(lines))
    return True


def _show_results_fallback(title: str, rows: list[dict], *, apply_one, apply_many, jump_local) -> None:
    ida_kernwin.msg(f"[*] {title}: {len(rows)} result(s)\n")
    for index, row in enumerate(rows, start=1):
        ida_kernwin.msg(_format_row(index, row) + "\n")

    choice = ida_kernwin.ask_long(
        0,
        f"{title}: enter a result number to act on, -1 to apply all selected rows, or 0 to cancel. See the Output window for details.",
    )
    if choice is None or choice == 0:
        return
    if choice == -1:
        apply_many(rows)
        return
    if choice < 1 or choice > len(rows):
        raise RuntimeError(f"invalid result selection: {choice}")

    row = rows[choice - 1]
    action = ida_kernwin.ask_yn(
        ida_kernwin.ASKBTN_YES,
        "Yes: jump to local function/item\nNo: apply the selected match name\nCancel: abort",
    )
    if action == ida_kernwin.ASKBTN_CANCEL:
        return
    if action == ida_kernwin.ASKBTN_YES:
        jump_local(row)
        return
    apply_one(row)


def show_results(
    title: str,
    rows: list[dict],
    *,
    apply_one,
    apply_many,
    jump_local,
) -> None:
    if not rows:
        ida_kernwin.msg(f"[*] {title}: no results\n")
        return

    try:
        _, QtCore, QtGui, QtWidgets = import_qt()
    except Exception:
        _show_results_fallback(
            title,
            rows,
            apply_one=apply_one,
            apply_many=apply_many,
            jump_local=jump_local,
        )
        return

    class ResultsDialog(QtWidgets.QDialog):
        def __init__(self) -> None:
            super().__init__(None)
            self.setWindowTitle(title)
            self.resize(1220, 680)

            layout = QtWidgets.QVBoxLayout(self)

            filter_row = QtWidgets.QHBoxLayout()
            filter_label = QtWidgets.QLabel("Filter", self)
            self.filter_edit = QtWidgets.QLineEdit(self)
            self.filter_edit.setPlaceholderText("name, corpus, address, sha256")
            filter_row.addWidget(filter_label)
            filter_row.addWidget(self.filter_edit)
            layout.addLayout(filter_row)

            self.model = QtGui.QStandardItemModel(len(rows), 7, self)
            self.model.setHorizontalHeaderLabels(
                [
                    "Local Name",
                    "Local Address",
                    "Match Name",
                    "Match Address",
                    "Score",
                    "Corpus",
                    "SHA256",
                ]
            )

            for row_index, row in enumerate(rows):
                values = [
                    str(row["local_name"]),
                    hex(int(row["local_address"])),
                    str(row["match_name"]),
                    hex(int(row["match_address"])),
                    f"{float(row['score']):.6f}",
                    str(row["corpus"]),
                    str(row["sha256"]),
                ]
                for column, value in enumerate(values):
                    item = QtGui.QStandardItem(value)
                    item.setEditable(False)
                    item.setData(row_index, QtCore.Qt.UserRole)
                    if column == 4:
                        item.setData(float(row["score"]), QtCore.Qt.UserRole + 1)
                    self.model.setItem(row_index, column, item)

            self.proxy = QtCore.QSortFilterProxyModel(self)
            self.proxy.setSourceModel(self.model)
            self.proxy.setFilterCaseSensitivity(QtCore.Qt.CaseInsensitive)
            self.proxy.setFilterKeyColumn(-1)
            self.proxy.setSortCaseSensitivity(QtCore.Qt.CaseInsensitive)

            self.table = QtWidgets.QTableView(self)
            self.table.setModel(self.proxy)
            self.table.setSortingEnabled(True)
            self.table.sortByColumn(4, QtCore.Qt.DescendingOrder)
            self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
            self.table.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
            self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
            self.table.setAlternatingRowColors(True)
            self.table.horizontalHeader().setStretchLastSection(True)
            self.table.verticalHeader().setVisible(False)
            self.table.doubleClicked.connect(self._jump_to_current)
            layout.addWidget(self.table)

            threshold_row = QtWidgets.QHBoxLayout()
            threshold_label = QtWidgets.QLabel("Threshold", self)
            self.threshold_spin = QtWidgets.QDoubleSpinBox(self)
            self.threshold_spin.setRange(0.0, 1.0)
            self.threshold_spin.setDecimals(6)
            self.threshold_spin.setSingleStep(0.01)
            self.threshold_spin.setValue(0.900000)
            threshold_row.addWidget(threshold_label)
            threshold_row.addWidget(self.threshold_spin)
            threshold_row.addStretch(1)
            layout.addLayout(threshold_row)

            buttons = QtWidgets.QDialogButtonBox(self)
            self.jump_button = buttons.addButton("Jump", QtWidgets.QDialogButtonBox.ActionRole)
            self.apply_one_button = buttons.addButton("Apply One", QtWidgets.QDialogButtonBox.ActionRole)
            self.apply_selected_button = buttons.addButton("Apply Selected", QtWidgets.QDialogButtonBox.ActionRole)
            self.apply_threshold_button = buttons.addButton("Apply Above Threshold", QtWidgets.QDialogButtonBox.ActionRole)
            self.copy_cells_button = buttons.addButton("Copy Cell", QtWidgets.QDialogButtonBox.ActionRole)
            self.copy_rows_button = buttons.addButton("Copy Rows", QtWidgets.QDialogButtonBox.ActionRole)
            self.close_button = buttons.addButton(QtWidgets.QDialogButtonBox.Close)
            layout.addWidget(buttons)

            self.filter_edit.textChanged.connect(self.proxy.setFilterFixedString)
            self.jump_button.clicked.connect(self._jump_to_current)
            self.apply_one_button.clicked.connect(self._apply_one_current)
            self.apply_selected_button.clicked.connect(self._apply_selected)
            self.apply_threshold_button.clicked.connect(self._apply_threshold)
            self.copy_cells_button.clicked.connect(self._copy_cells)
            self.copy_rows_button.clicked.connect(self._copy_rows)
            self.close_button.clicked.connect(self.reject)

            copy_shortcut = QtWidgets.QShortcut(QtGui.QKeySequence.Copy, self.table)
            copy_shortcut.activated.connect(self._copy_cells)

        def _selected_source_rows(self) -> list[int]:
            selected = self.table.selectionModel().selectedRows()
            source_rows: list[int] = []
            seen: set[int] = set()
            for index in selected:
                source_index = self.proxy.mapToSource(index)
                row_index = int(self.model.item(source_index.row(), 0).data(QtCore.Qt.UserRole))
                if row_index in seen:
                    continue
                seen.add(row_index)
                source_rows.append(row_index)
            return source_rows

        def _selected_rows(self) -> list[dict]:
            return [rows[index] for index in self._selected_source_rows()]

        def _current_row(self) -> dict | None:
            current = self.table.currentIndex()
            if not current.isValid():
                selected_rows = self._selected_rows()
                return selected_rows[0] if selected_rows else None
            source_index = self.proxy.mapToSource(current)
            row_index = int(self.model.item(source_index.row(), 0).data(QtCore.Qt.UserRole))
            return rows[row_index]

        def _visible_rows(self) -> list[dict]:
            visible: list[dict] = []
            for row_index in range(self.proxy.rowCount()):
                source_index = self.proxy.mapToSource(self.proxy.index(row_index, 0))
                source_row = int(self.model.item(source_index.row(), 0).data(QtCore.Qt.UserRole))
                visible.append(rows[source_row])
            return visible

        def _jump_to_current(self, *_args) -> None:
            row = self._current_row()
            if row is None:
                return
            jump_local(row)
            self.table.setFocus()

        def _apply_one_current(self, *_args) -> None:
            row = self._current_row()
            if row is None:
                return
            apply_one(row)

        def _apply_selected(self, *_args) -> None:
            selected_rows = self._selected_rows()
            if not selected_rows:
                row = self._current_row()
                if row is None:
                    return
                selected_rows = [row]
            apply_many(selected_rows)

        def _apply_threshold(self, *_args) -> None:
            threshold = float(self.threshold_spin.value())
            selected_rows = [row for row in self._visible_rows() if float(row["score"]) >= threshold]
            if not selected_rows:
                ida_kernwin.msg(f"[*] {title}: no visible rows at or above {threshold:.6f}\n")
                return
            apply_many(selected_rows)

        def _copy_cells(self, *_args) -> None:
            current = self.table.currentIndex()
            if not current.isValid():
                return
            QtGui.QGuiApplication.clipboard().setText(str(current.data()))

        def _copy_rows(self, *_args) -> None:
            selected_rows = self._selected_rows()
            if not selected_rows:
                row = self._current_row()
                if row is None:
                    return
                selected_rows = [row]
            if not _copy_rows_to_clipboard(selected_rows):
                raise RuntimeError("Qt clipboard is not available")

    dialog = ResultsDialog()
    exec_dialog(dialog)
