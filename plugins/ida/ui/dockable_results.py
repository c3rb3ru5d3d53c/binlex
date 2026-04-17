"""Dockable results widget for IDA Pro"""
from __future__ import annotations

import ida_kernwin
import idaapi

try:
    from qt_compat import exec_dialog, import_qt
except ModuleNotFoundError:
    from ..qt_compat import exec_dialog, import_qt

try:
    from ui.results import (
        CorporaPopoverDialog,
        TagsPopoverDialog,
        CommentsPopoverDialog,
        SymbolSelectorDialog,
        _symbol_display,
        _corpora_display,
        _tags_display,
        _comments_display,
    )
except (ModuleNotFoundError, ImportError):
    from .results import (
        CorporaPopoverDialog,
        TagsPopoverDialog,
        CommentsPopoverDialog,
        SymbolSelectorDialog,
        _symbol_display,
        _corpora_display,
        _tags_display,
        _comments_display,
    )


class BinlexResultsForm(idaapi.PluginForm):
    """Dockable form for Binlex search results"""

    def __init__(self, title: str, rows: list[dict], apply_one, apply_many, jump_local, web_client):
        super(BinlexResultsForm, self).__init__()
        self._title = title
        self._rows = rows
        self._apply_one = apply_one
        self._apply_many = apply_many
        self._jump_local = jump_local
        self._web_client = web_client
        self._widget = None
        self._form = None

    def OnCreate(self, form):
        """Called when the widget is created"""
        try:
            self._form = self.FormToPySideWidget(form)
        except Exception:
            self._form = self.FormToPyQtWidget(form)

        self._widget = ResultsWidget(
            self._title,
            self._rows,
            self._apply_one,
            self._apply_many,
            self._jump_local,
            self._web_client,
            parent=self._form
        )

        _, QtCore, _, QtWidgets = import_qt()
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self._widget)
        self._form.setLayout(layout)

    def OnClose(self, form):
        """Called when the widget is closed"""
        self._widget = None

    def Show(self):
        """Show the dockable widget"""
        return idaapi.PluginForm.Show(
            self,
            self._title,
            options=idaapi.PluginForm.WOPN_RESTORE | idaapi.PluginForm.WCLS_SAVE
        )


class ResultsWidget:
    """The actual results table widget"""

    def __init__(self, title, rows, apply_one, apply_many, jump_local, web_client, parent=None):
        _, QtCore, QtGui, QtWidgets = import_qt()

        self.title = title
        self.rows = rows
        self.apply_one = apply_one
        self.apply_many = apply_many
        self.jump_local = jump_local
        self.web = web_client

        self.widget = QtWidgets.QWidget(parent)
        self._populate_ui()

    def _populate_ui(self):
        _, QtCore, QtGui, QtWidgets = import_qt()

        layout = QtWidgets.QVBoxLayout(self.widget)

        filter_row = QtWidgets.QHBoxLayout()
        filter_label = QtWidgets.QLabel("Filter", self.widget)
        self.filter_edit = QtWidgets.QLineEdit(self.widget)
        self.filter_edit.setPlaceholderText("name, corpus, address, sha256")
        filter_row.addWidget(filter_label)
        filter_row.addWidget(self.filter_edit)
        layout.addLayout(filter_row)

        self.model = QtGui.QStandardItemModel(len(self.rows), 10, self.widget)
        self.model.setHorizontalHeaderLabels(
            [
                "Local Name",
                "Local Address",
                "Symbols",
                "Match Address",
                "Score",
                "Corpora",
                "SHA256",
                "Tags",
                "Comments",
                "Architecture",
            ]
        )

        for row_index, row in enumerate(self.rows):
            symbols_display = _symbol_display(row.get("symbols", []))
            corpora_display = _corpora_display(row.get("corpora", []))
            tags_display = _tags_display(row.get("tags", []))
            comments_display = _comments_display(row.get("comments", []))
            values = [
                str(row["local_name"]),
                hex(int(row["local_address"])),
                symbols_display,
                hex(int(row["match_address"])),
                f"{float(row['score']):.6f}",
                corpora_display,
                str(row["sha256"]),
                tags_display,
                comments_display,
                str(row.get("architecture", "")),
            ]
            for column, value in enumerate(values):
                item = QtGui.QStandardItem(value)
                item.setEditable(False)
                item.setData(row_index, QtCore.Qt.UserRole)
                if column == 4:
                    item.setData(float(row["score"]), QtCore.Qt.UserRole + 1)
                self.model.setItem(row_index, column, item)

        self.proxy = QtCore.QSortFilterProxyModel(self.widget)
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterCaseSensitivity(QtCore.Qt.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)
        self.proxy.setSortCaseSensitivity(QtCore.Qt.CaseInsensitive)

        self.table = QtWidgets.QTableView(self.widget)
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(4, QtCore.Qt.DescendingOrder)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.doubleClicked.connect(self._on_table_double_click)
        self.table.clicked.connect(self._on_table_click)
        self.table.selectionModel().currentRowChanged.connect(self._on_row_changed)
        layout.addWidget(self.table)

        self.filter_edit.textChanged.connect(self.proxy.setFilterFixedString)

    def _selected_source_rows(self) -> list[int]:
        _, QtCore, _, _ = import_qt()
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
        return [self.rows[index] for index in self._selected_source_rows()]

    def _current_row(self) -> dict | None:
        _, QtCore, _, _ = import_qt()
        current = self.table.currentIndex()
        if not current.isValid():
            selected_rows = self._selected_rows()
            return selected_rows[0] if selected_rows else None
        source_index = self.proxy.mapToSource(current)
        row_index = int(self.model.item(source_index.row(), 0).data(QtCore.Qt.UserRole))
        return self.rows[row_index]

    def _on_row_changed(self, current, previous):
        """Auto-jump to local address when row selection changes."""
        _, QtCore, _, _ = import_qt()
        if not current.isValid():
            return
        source_index = self.proxy.mapToSource(current)
        row_index = int(self.model.item(source_index.row(), 0).data(QtCore.Qt.UserRole))
        row = self.rows[row_index]
        self.jump_local(row)

    def _on_table_click(self, index):
        """Handle click on table - open appropriate dialog based on column."""
        column = index.column()
        if column == 2:  # Symbols column
            self._open_symbol_selector()
        elif column == 5:  # Corpus column
            self._open_corpora_popover()
        elif column == 7:  # Tags column
            self._open_tags_popover()
        elif column == 8:  # Comments column
            self._open_comments_popover()

    def _on_table_double_click(self, index):
        """Handle double-click on table - if not metadata column, jump to local."""
        column = index.column()
        if column not in (2, 5, 7, 8):  # Not Symbols, Corpus, Tags, or Comments columns
            self._jump_to_current()

    def _open_corpora_popover(self) -> None:
        """Open the corpora popover dialog."""
        row = self._current_row()
        if row is None:
            return

        popover = CorporaPopoverDialog(row, self.web, self.widget)
        popover.show()
        self._refresh_current_row()

    def _open_tags_popover(self) -> None:
        """Open the tags popover dialog."""
        row = self._current_row()
        if row is None:
            return

        popover = TagsPopoverDialog(row, self.web, self.widget)
        popover.show()
        self._refresh_current_row()

    def _open_comments_popover(self) -> None:
        """Open the comments popover dialog."""
        row = self._current_row()
        if row is None:
            return

        popover = CommentsPopoverDialog(row, self.web, self.widget)
        popover.show()
        self._refresh_current_row()

    def _refresh_current_row(self) -> None:
        """Refresh the current row in the table after metadata changes."""
        _, QtCore, _, _ = import_qt()
        current = self.table.currentIndex()
        if not current.isValid():
            return

        source_index = self.proxy.mapToSource(current)
        row_index = int(self.model.item(source_index.row(), 0).data(QtCore.Qt.UserRole))
        row = self.rows[row_index]

        # Update the table cells for corpora, tags, and comments
        corpora_display = _corpora_display(row.get("corpora", []))
        tags_display = _tags_display(row.get("tags", []))
        comments_display = _comments_display(row.get("comments", []))
        symbols_display = _symbol_display(row.get("symbols", []))

        corpora_item = self.model.item(source_index.row(), 5)
        tags_item = self.model.item(source_index.row(), 7)
        comments_item = self.model.item(source_index.row(), 8)
        symbols_item = self.model.item(source_index.row(), 2)

        if corpora_item:
            corpora_item.setText(corpora_display)
        if tags_item:
            tags_item.setText(tags_display)
        if comments_item:
            comments_item.setText(comments_display)
        if symbols_item:
            symbols_item.setText(symbols_display)

    def _open_symbol_selector(self) -> None:
        """Open the symbol selector dialog and optionally apply selected symbol."""
        try:
            import idaapi
            import idc
            from binlex.plugins.ida.core.config import is_meaningful_name
        except ImportError:
            try:
                import idaapi
                import idc
                from core.config import is_meaningful_name
            except ImportError:
                ida_kernwin.msg("[!] Failed to import required modules\n")
                return

        row = self._current_row()
        if row is None:
            return

        symbols = row.get("symbols", [])
        selector = SymbolSelectorDialog(row, self.web, self.widget)
        selected_symbol = selector.show()

        if selected_symbol:
            function_address = int(row["local_function_address"])
            current_name = idc.get_func_name(function_address) or ""

            if is_meaningful_name(current_name) and current_name != selected_symbol:
                result = ida_kernwin.ask_yn(
                    ida_kernwin.ASKBTN_NO,
                    f"Overwrite existing function name '{current_name}' at {hex(function_address)} with '{selected_symbol}'?",
                )
                if result != ida_kernwin.ASKBTN_YES:
                    return

            idaapi.set_name(function_address, selected_symbol, idaapi.SN_FORCE)
            comment = (
                "Binlex match\n"
                f"name: {selected_symbol}\n"
                f"score: {row['score']:.6f}\n"
                f"sha256: {row['sha256']}\n"
                f"corpora: {', '.join(row.get('corpora', []))}\n"
                f"match_address: {hex(int(row['match_address']))}\n"
            )
            function = idaapi.get_func(function_address)
            if function is not None:
                idaapi.set_func_cmt(function, comment, True)

            ida_kernwin.msg(f"[*] Applied symbol '{selected_symbol}' to {hex(function_address)}\n")
            self._refresh_current_row()

    def _jump_to_current(self, *_args) -> None:
        row = self._current_row()
        if row is None:
            return
        self.jump_local(row)
        self.table.setFocus()


def show_results_dockable(
    title: str,
    rows: list[dict],
    *,
    apply_one,
    apply_many,
    jump_local,
    web_client,
) -> None:
    """Show results in a dockable IDA widget"""
    if not rows:
        ida_kernwin.msg(f"[*] {title}: no results\n")
        return

    form = BinlexResultsForm(
        title,
        rows,
        apply_one,
        apply_many,
        jump_local,
        web_client
    )
    form.Show()
