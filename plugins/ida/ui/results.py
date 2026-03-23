from __future__ import annotations

from typing import Callable

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QKeySequence
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)


COLUMNS = [
    ("Local Address", "local_address"),
    ("Local Name", "local_name"),
    ("Score", "score"),
    ("Match Address", "match_address"),
    ("Match Name", "match_name"),
    ("SHA256", "sha256"),
    ("Corpus", "corpus"),
]


class ResultTable(QTableWidget):
    def keyPressEvent(self, event) -> None:  # noqa: N802
        if event.matches(QKeySequence.Copy):
            self.copy_selection()
            return
        super().keyPressEvent(event)

    def copy_selection(self) -> None:
        indexes = self.selectedIndexes()
        if not indexes:
            return
        rows = sorted({index.row() for index in indexes})
        cols = sorted({index.column() for index in indexes})
        lines = []
        for row in rows:
            cells = []
            for col in cols:
                item = self.item(row, col)
                cells.append("" if item is None else item.text())
            lines.append("\t".join(cells))
        from PyQt5.QtWidgets import QApplication

        QApplication.clipboard().setText("\n".join(lines))


class ResultsDialog(QDialog):
    def __init__(
        self,
        title: str,
        rows: list[dict],
        *,
        apply_one: Callable[[dict], None],
        apply_many: Callable[[list[dict]], None],
        jump_local: Callable[[dict], None],
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(1000, 640)
        self._rows = rows
        self._apply_one = apply_one
        self._apply_many = apply_many
        self._jump_local = jump_local

        self.global_filter = QLineEdit()
        self.local_name_filter = QLineEdit()
        self.match_name_filter = QLineEdit()
        self.sha256_filter = QLineEdit()
        self.corpus_filter = QLineEdit()
        self.min_score_filter = QDoubleSpinBox()
        self.min_score_filter.setRange(0.0, 1.0)
        self.min_score_filter.setSingleStep(0.01)
        self.min_score_filter.setValue(0.0)

        self.table = ResultTable(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels([label for label, _ in COLUMNS])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._open_menu)
        self.table.itemDoubleClicked.connect(self._on_double_click)

        layout = QVBoxLayout(self)

        filter_form = QFormLayout()
        filter_form.addRow("Search", self.global_filter)
        filter_form.addRow("Local Name", self.local_name_filter)
        filter_form.addRow("Match Name", self.match_name_filter)
        filter_form.addRow("SHA256", self.sha256_filter)
        filter_form.addRow("Corpus", self.corpus_filter)
        filter_form.addRow("Min Score", self.min_score_filter)
        layout.addLayout(filter_form)
        layout.addWidget(self.table)

        buttons = QHBoxLayout()
        copy_button = QPushButton("Copy")
        copy_button.clicked.connect(self.table.copy_selection)
        apply_button = QPushButton("Apply Selected")
        apply_button.clicked.connect(self._apply_selected)
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        buttons.addWidget(copy_button)
        buttons.addWidget(apply_button)
        buttons.addStretch(1)
        buttons.addWidget(close_button)
        layout.addLayout(buttons)

        self.global_filter.textChanged.connect(self._apply_filters)
        self.local_name_filter.textChanged.connect(self._apply_filters)
        self.match_name_filter.textChanged.connect(self._apply_filters)
        self.sha256_filter.textChanged.connect(self._apply_filters)
        self.corpus_filter.textChanged.connect(self._apply_filters)
        self.min_score_filter.valueChanged.connect(self._apply_filters)

        self._populate()
        self._apply_filters()

    def _populate(self) -> None:
        self.table.setRowCount(len(self._rows))
        for row_index, row in enumerate(self._rows):
            for col_index, (_, key) in enumerate(COLUMNS):
                value = row[key]
                if key.endswith("address"):
                    text = hex(int(value))
                elif key == "score":
                    text = f"{float(value):.6f}"
                else:
                    text = str(value)
                item = QTableWidgetItem(text)
                if col_index == 0:
                    item.setData(Qt.UserRole, row)
                self.table.setItem(row_index, col_index, item)
        self.table.resizeColumnsToContents()

    def _row_payload(self, row_index: int) -> dict:
        return self.table.item(row_index, 0).data(Qt.UserRole)

    def _selected_payloads(self) -> list[dict]:
        rows = sorted({item.row() for item in self.table.selectedItems()})
        return [self._row_payload(row) for row in rows]

    def _open_menu(self, position) -> None:
        menu = QMenu(self)
        apply_one = menu.addAction("Apply Name")
        apply_many = menu.addAction("Apply Names")
        jump_local = menu.addAction("Jump Local")
        copy_action = menu.addAction("Copy")
        action = menu.exec_(self.table.viewport().mapToGlobal(position))
        if action == apply_one:
            payloads = self._selected_payloads()
            if payloads:
                self._apply_one(payloads[0])
        elif action == apply_many:
            payloads = self._selected_payloads()
            if payloads:
                self._apply_many(payloads)
        elif action == jump_local:
            payloads = self._selected_payloads()
            if payloads:
                self._jump_local(payloads[0])
        elif action == copy_action:
            self.table.copy_selection()

    def _on_double_click(self, item) -> None:
        self._jump_local(self._row_payload(item.row()))

    def _apply_selected(self) -> None:
        payloads = self._selected_payloads()
        if payloads:
            self._apply_many(payloads)

    def _apply_filters(self) -> None:
        global_value = self.global_filter.text().strip().lower()
        local_name = self.local_name_filter.text().strip().lower()
        match_name = self.match_name_filter.text().strip().lower()
        sha256 = self.sha256_filter.text().strip().lower()
        corpus = self.corpus_filter.text().strip().lower()
        min_score = self.min_score_filter.value()

        for row_index in range(self.table.rowCount()):
            row = self._row_payload(row_index)
            searchable = " ".join(
                [
                    hex(int(row["local_address"])),
                    row["local_name"],
                    f"{float(row['score']):.6f}",
                    hex(int(row["match_address"])),
                    row["match_name"],
                    row["sha256"],
                    row["corpus"],
                ]
            ).lower()
            hidden = False
            if global_value and global_value not in searchable:
                hidden = True
            if local_name and local_name not in row["local_name"].lower():
                hidden = True
            if match_name and match_name not in row["match_name"].lower():
                hidden = True
            if sha256 and sha256 not in row["sha256"].lower():
                hidden = True
            if corpus and corpus not in row["corpus"].lower():
                hidden = True
            if float(row["score"]) < min_score:
                hidden = True
            self.table.setRowHidden(row_index, hidden)
