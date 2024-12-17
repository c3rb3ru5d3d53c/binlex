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
        """
        :param data: 2D list of table rows
        :param headers: list of column headers
        :param color_column: (int) index of the column used for color mapping, or None
        :param min_value, max_value: numeric range for color mapping
        :param low_to_high: if True, low value is red and high value is green
        :param default_filter_column: Which column index to filter on by default
        :param default_sort_column: Which column index to sort by when the table is created
        :param default_sort_ascending: Boolean; True = ascending sort, False = descending
        """
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
        for col_idx, header in enumerate(self.headers):
            action = menu.addAction(f"Copy {header}")
            column_actions[action] = col_idx
        selected_action = menu.exec_(self.table_view.viewport().mapToGlobal(position))
        if selected_action in column_actions:
            self.copy_column_data(column_actions[selected_action])

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