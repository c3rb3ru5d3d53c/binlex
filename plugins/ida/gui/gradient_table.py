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

from PyQt5.QtCore import Qt, QSortFilterProxyModel
from PyQt5.QtGui import QBrush, QColor, QPainter, QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import (
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableView,
    QHeaderView,
    QVBoxLayout,
    QComboBox,
    QLineEdit,
    QMenu,
    QApplication,
    QWidget,
    QStyle,
    QAbstractItemView,
)
import idaapi
import idc
import ida_kernwin

class BoldSelectedRowDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        painter.save()
        custom_option = QStyleOptionViewItem(option)

        if custom_option.state & QStyle.State_Selected:
            custom_option.state &= ~QStyle.State_Selected
            background_brush = index.data(Qt.BackgroundRole)
            if isinstance(background_brush, QBrush):
                painter.fillRect(custom_option.rect, background_brush)
            custom_option.font.setBold(True)
            painter.setFont(custom_option.font)

        super().paint(painter, custom_option, index)
        painter.restore()

class TableFilterProxyModel(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.filter_string = ""
        self.filter_column = 0
        self.setFilterCaseSensitivity(Qt.CaseInsensitive)

    def setFilterString(self, text):
        self.filter_string = text.lower()
        self.invalidateFilter()

    def setFilterColumnIndex(self, col_index):
        self.filter_column = col_index
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        if not self.filter_string:
            return True
        index = self.sourceModel().index(source_row, self.filter_column, source_parent)
        cell_text = index.data(Qt.DisplayRole)
        if cell_text is None:
            return False
        return self.filter_string in cell_text.lower()

class GradientTable(ida_kernwin.PluginForm):
    # def __init__(
    #     self,
    #     data,
    #     headers,
    #     color_column=None,
    #     min_value=0,
    #     max_value=1,
    #     low_to_high=True,
    #     default_filter_column=0,
    #     default_sort_column=0,
    #     default_sort_ascending=True
    # ):
    #     super().__init__()
    #     self.data = data
    #     self.headers = headers
    #     self.color_column = color_column
    #     self.min_value = min_value
    #     self.max_value = max_value
    #     self.low_to_high = low_to_high
    #     self.default_filter_column = default_filter_column
    #     self.default_sort_column = default_sort_column
    #     self.default_sort_ascending = default_sort_ascending

    #     self.model = None
    #     self.proxy_model = None
    #     self.table_view = None
    #     self.column_combo_box = None
    #     self.filter_line_edit = None

    #     self.row_callbacks = []
    #     self.table_callbacks = []

    def __init__(
        self,
        data,
        headers,
        color_column=None,
        min_value=0,
        max_value=1,
        low_to_high=True,
        default_filter_column=0,
        default_sort_column=0,
        default_sort_ascending=True
    ):
        super().__init__()
        self.data = data
        self.headers = headers
        self.color_column = color_column
        self.min_value = min_value
        self.max_value = max_value
        self.low_to_high = low_to_high
        self.default_filter_column = default_filter_column
        self.default_sort_column = default_sort_column
        self.default_sort_ascending = default_sort_ascending

        self.model = None
        self.proxy_model = None
        self.table_view = None
        self.column_combo_box = None
        self.filter_line_edit = None

        self.row_callbacks = []
        self.table_callbacks = []

    def register_table_callback(self, menu_text, callback):
        """Register a full-table callback to be added to the context menu."""
        self.table_callbacks.append((menu_text, callback))

    def register_row_callback(self, menu_text, callback):
        """Register a row callback to be added to the context menu."""
        self.row_callbacks.append((menu_text, callback))

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()

        self.model = QStandardItemModel(len(self.data), len(self.headers), self.parent)
        self.model.setHorizontalHeaderLabels(self.headers)

        for row_idx, row_data in enumerate(self.data):
            row_color = None
            if self.color_column is not None:
                try:
                    value = float(row_data[self.color_column])
                    row_color = self.get_color(value)
                except ValueError:
                    pass

            for col_idx, col_data in enumerate(row_data):
                item = QStandardItem(str(col_data))
                if row_color:
                    brush = QBrush(row_color)
                    item.setBackground(brush)
                    fg_color = self.get_contrasting_color(row_color)
                    item.setForeground(QBrush(fg_color))
                item.setEditable(False)
                self.model.setItem(row_idx, col_idx, item)

        self.proxy_model = TableFilterProxyModel(self.parent)
        self.proxy_model.setSourceModel(self.model)
        self.proxy_model.setDynamicSortFilter(True)

        self.table_view = QTableView(self.parent)
        self.table_view.setModel(self.proxy_model)
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table_view.setSortingEnabled(True)

        sort_order = Qt.AscendingOrder if self.default_sort_ascending else Qt.DescendingOrder
        self.table_view.sortByColumn(self.default_sort_column, sort_order)

        self.table_view.verticalHeader().setVisible(False)

        self.table_view.horizontalHeader().setStretchLastSection(True)
        self.table_view.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

        delegate = BoldSelectedRowDelegate(self.table_view)
        self.table_view.setItemDelegate(delegate)

        self.table_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table_view.customContextMenuRequested.connect(self.show_context_menu)

        selection_model = self.table_view.selectionModel()
        selection_model.selectionChanged.connect(self.on_row_selected)

        main_layout.addWidget(self.table_view)

        filter_layout = QVBoxLayout()

        self.column_combo_box = QComboBox()
        self.column_combo_box.addItems(self.headers)
        self.column_combo_box.setCurrentIndex(self.default_filter_column)
        self.column_combo_box.currentIndexChanged.connect(self.on_filter_column_changed)

        self.filter_line_edit = QLineEdit()
        self.filter_line_edit.setPlaceholderText("Type to filter...")
        self.filter_line_edit.textChanged.connect(self.on_filter_text_changed)

        filter_layout.addWidget(self.column_combo_box)
        filter_layout.addWidget(self.filter_line_edit)

        main_layout.addLayout(filter_layout)
        self.parent.setLayout(main_layout)

        self.proxy_model.setFilterColumnIndex(self.default_filter_column)

    def on_filter_column_changed(self, index):
        self.proxy_model.setFilterColumnIndex(index)

    def on_filter_text_changed(self, text):
        self.proxy_model.setFilterString(text)

    def on_row_selected(self, selected, deselected):
        indices = self.table_view.selectionModel().selectedRows()
        if not indices:
            return

        proxy_index = indices[0]
        source_index = self.proxy_model.mapToSource(proxy_index)
        item = self.model.item(source_index.row(), 0)
        if not item:
            return

        hex_text = item.text()
        try:
            address = int(hex_text, 16)
            idc.jumpto(address)
        except ValueError:
            ida_kernwin.msg('[x] invalid address format\n')

    def show_context_menu(self, position):
        menu = QMenu(self.table_view)
        column_actions = {}

        # Add "Copy" actions for each column
        for col_idx, header in enumerate(self.headers):
            action = menu.addAction(f"Copy {header}")
            column_actions[action] = col_idx

        # Add row callbacks
        if self.row_callbacks:
            menu.addSeparator()
        for menu_text, callback in self.row_callbacks:
            action = menu.addAction(menu_text)
            column_actions[action] = callback

        # Add full-table callbacks
        if self.table_callbacks:
            menu.addSeparator()
        for menu_text, callback in self.table_callbacks:
            action = menu.addAction(menu_text)
            column_actions[action] = callback

        selected_action = menu.exec_(self.table_view.viewport().mapToGlobal(position))
        if selected_action in column_actions:
            selected_item = column_actions[selected_action]
            if callable(selected_item):
                if selected_item in dict(self.row_callbacks).values():
                    # Execute the row callback
                    self.execute_row_callback(selected_item)
                elif selected_item in dict(self.table_callbacks).values():
                    # Execute the full-table callback
                    self.execute_table_callback(selected_item)
            else:
                self.copy_column_data(selected_item)

    def execute_table_callback(self, callback):
        """Execute a table callback."""
        table_data = []
        for row_idx in range(self.model.rowCount()):
            row_data = [
                self.model.item(row_idx, col_idx).text()
                for col_idx in range(self.model.columnCount())
            ]
            table_data.append(row_data)
        callback(table_data)

    # def show_context_menu(self, position):
    #     menu = QMenu(self.table_view)
    #     column_actions = {}

    #     # Add "Copy" actions for each column
    #     for col_idx, header in enumerate(self.headers):
    #         action = menu.addAction(f"Copy {header}")
    #         column_actions[action] = col_idx

    #     # Add row callbacks
    #     if self.row_callbacks:
    #         menu.addSeparator()
    #     for menu_text, callback in self.row_callbacks:
    #         action = menu.addAction(menu_text)
    #         column_actions[action] = callback

    #     selected_action = menu.exec_(self.table_view.viewport().mapToGlobal(position))
    #     if selected_action in column_actions:
    #         selected_item = column_actions[selected_action]
    #         if callable(selected_item):
    #             # Execute the row callback
    #             self.execute_row_callback(selected_item)
    #         else:
    #             self.copy_column_data(selected_item)

    def execute_row_callback(self, callback):
        """Execute a row callback on the selected row."""
        selection_model = self.table_view.selectionModel()
        if not selection_model.hasSelection():
            return
        proxy_index = selection_model.selectedRows()[0]
        source_index = self.proxy_model.mapToSource(proxy_index)
        row_data = [
            self.model.item(source_index.row(), col_idx).text()
            for col_idx in range(self.model.columnCount())
        ]
        callback(row_data)

    def copy_column_data(self, column_index):
        selection_model = self.table_view.selectionModel()
        if not selection_model.hasSelection():
            return
        proxy_index = selection_model.selectedRows()[0]
        source_index = self.proxy_model.mapToSource(proxy_index)
        item = self.model.item(source_index.row(), column_index)
        if item:
            clipboard = QApplication.clipboard()
            clipboard.setText(item.text())

    def get_color(self, value):
        normalized = (value - self.min_value) / (self.max_value - self.min_value)
        normalized = max(0, min(1, normalized))
        if not self.low_to_high:
            normalized = 1 - normalized
        red = int((1 - normalized) * 255)
        green = int(normalized * 255)
        return QColor(red, green, 0)

    def get_contrasting_color(self, color: QColor) -> QColor:
        r = color.redF()
        g = color.greenF()
        b = color.blueF()
        luminance = 0.299*r + 0.587*g + 0.114*b
        return Qt.black if luminance >= 0.5 else Qt.white
