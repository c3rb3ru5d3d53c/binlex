from __future__ import annotations

import ida_kernwin

from core.search import SearchRequest
from core.config import PluginConfig
from core.indexing import IndexRequest

try:
    from qt_compat import exec_dialog, import_qt
except ModuleNotFoundError:  # pragma: no cover - fallback for packaged package layouts
    from ..qt_compat import exec_dialog, import_qt


def _parse_corpora(value: str) -> list[str]:
    corpora = []
    seen = set()
    for item in value.split(","):
        corpus = item.strip()
        if not corpus or corpus in seen:
            continue
        corpora.append(corpus)
        seen.add(corpus)
    return corpora


def prompt_index(
    title: str,
    plugin_config: PluginConfig,
    *,
    allow_index_blocks: bool,
) -> IndexRequest | None:
    _, QtCore, _, QtWidgets = import_qt()

    class PillWidget(QtWidgets.QWidget):
        """A pill-shaped widget with a label and arrow button."""

        def __init__(self, text: str, arrow_direction: str, parent=None):
            super().__init__(parent)
            self.text = text
            self.arrow_direction = arrow_direction

            # Set attribute to ensure stylesheet is respected
            self.setAttribute(QtCore.Qt.WA_StyledBackground, True)

            layout = QtWidgets.QHBoxLayout(self)
            layout.setContentsMargins(8, 4, 8, 4)
            layout.setSpacing(4)

            if arrow_direction == "left":
                self.arrow_btn = QtWidgets.QPushButton("←")
                self.arrow_btn.setFixedSize(20, 20)
                layout.addWidget(self.arrow_btn)

            self.label = QtWidgets.QLabel(text)
            layout.addWidget(self.label)

            if arrow_direction == "right":
                self.arrow_btn = QtWidgets.QPushButton("→")
                self.arrow_btn.setFixedSize(20, 20)
                layout.addWidget(self.arrow_btn)

            # Style as pill - using generic selectors like results.py
            self.setStyleSheet("""
                QWidget {
                    background-color: #e0e0e0;
                    border: 1px solid #b0b0b0;
                    border-radius: 12px;
                }
                QLabel {
                    color: #000000;
                    border: none;
                    background: transparent;
                }
                QPushButton {
                    background-color: transparent;
                    border: none;
                    font-weight: bold;
                    color: #000000;
                }
                QPushButton:hover {
                    background-color: #c0c0c0;
                    border-radius: 10px;
                }
            """)

    class FlowLayout(QtWidgets.QLayout):
        """Flow layout that wraps widgets."""

        def __init__(self, parent=None, margin=0, spacing=-1):
            super().__init__(parent)
            self.item_list = []
            self.setContentsMargins(margin, margin, margin, margin)
            self.setSpacing(spacing)

        def addItem(self, item):
            self.item_list.append(item)

        def count(self):
            return len(self.item_list)

        def itemAt(self, index):
            if 0 <= index < len(self.item_list):
                return self.item_list[index]
            return None

        def takeAt(self, index):
            if 0 <= index < len(self.item_list):
                return self.item_list.pop(index)
            return None

        def sizeHint(self):
            return self.minimumSize()

        def minimumSize(self):
            size = QtCore.QSize()
            for item in self.item_list:
                size = size.expandedTo(item.minimumSize())
            margin = self.contentsMargins()
            size += QtCore.QSize(margin.left() + margin.right(), margin.top() + margin.bottom())
            return size

        def setGeometry(self, rect):
            super().setGeometry(rect)
            self._do_layout(rect, False)

        def _do_layout(self, rect, test_only):
            x = rect.x()
            y = rect.y()
            line_height = 0

            for item in self.item_list:
                widget = item.widget()
                space_x = self.spacing()
                space_y = self.spacing()

                next_x = x + item.sizeHint().width() + space_x
                if next_x - space_x > rect.right() and line_height > 0:
                    x = rect.x()
                    y = y + line_height + space_y
                    next_x = x + item.sizeHint().width() + space_x
                    line_height = 0

                if not test_only:
                    item.setGeometry(QtCore.QRect(QtCore.QPoint(x, y), item.sizeHint()))

                x = next_x
                line_height = max(line_height, item.sizeHint().height())

            return y + line_height - rect.y()

    class DualListSelector(QtWidgets.QWidget):
        """Dual-list selector with pills for Available and Assigned items."""

        def __init__(self, title: str, parent=None):
            super().__init__(parent)
            self.available_items = []
            self.selected_items = []
            self.all_items = []

            layout = QtWidgets.QVBoxLayout(self)

            # Title
            title_label = QtWidgets.QLabel(title)
            title_label.setStyleSheet("font-weight: bold; font-size: 12pt;")
            layout.addWidget(title_label)

            # Dual list layout
            lists_layout = QtWidgets.QHBoxLayout()

            # Available (left)
            left_container = QtWidgets.QWidget()
            left_layout = QtWidgets.QVBoxLayout(left_container)
            left_layout.setContentsMargins(0, 0, 0, 0)
            left_label = QtWidgets.QLabel("Available")
            left_layout.addWidget(left_label)

            # Search for Available
            self.available_search_input = QtWidgets.QLineEdit()
            self.available_search_input.setPlaceholderText("Search available...")
            self.available_search_input.textChanged.connect(self._on_search_changed)
            left_layout.addWidget(self.available_search_input)

            self.available_scroll = QtWidgets.QScrollArea()
            self.available_scroll.setWidgetResizable(True)
            self.available_scroll.setMinimumHeight(200)
            self.available_container = QtWidgets.QWidget()
            self.available_layout = QtWidgets.QVBoxLayout(self.available_container)
            self.available_layout.setAlignment(QtCore.Qt.AlignTop)
            self.available_layout.setSpacing(5)
            self.available_scroll.setWidget(self.available_container)
            left_layout.addWidget(self.available_scroll)

            lists_layout.addWidget(left_container)

            # Selected (right)
            right_container = QtWidgets.QWidget()
            right_layout = QtWidgets.QVBoxLayout(right_container)
            right_layout.setContentsMargins(0, 0, 0, 0)
            right_label = QtWidgets.QLabel("Assigned")
            right_layout.addWidget(right_label)

            # Search for Assigned
            self.selected_search_input = QtWidgets.QLineEdit()
            self.selected_search_input.setPlaceholderText("Search assigned...")
            self.selected_search_input.textChanged.connect(self._on_search_changed)
            right_layout.addWidget(self.selected_search_input)

            self.selected_scroll = QtWidgets.QScrollArea()
            self.selected_scroll.setWidgetResizable(True)
            self.selected_scroll.setMinimumHeight(200)
            self.selected_container = QtWidgets.QWidget()
            self.selected_layout = QtWidgets.QVBoxLayout(self.selected_container)
            self.selected_layout.setAlignment(QtCore.Qt.AlignTop)
            self.selected_layout.setSpacing(5)
            self.selected_scroll.setWidget(self.selected_container)
            right_layout.addWidget(self.selected_scroll)

            lists_layout.addWidget(right_container)
            layout.addLayout(lists_layout)

        def set_items(self, items: list[str], selected: list[str] = None):
            """Set all available items and optionally pre-select some."""
            self.all_items = items
            self.selected_items = selected or []
            self.available_items = [item for item in items if item not in self.selected_items]
            self._update_display()

        def get_selected(self) -> list[str]:
            """Get list of selected items."""
            return self.selected_items.copy()

        def _on_search_changed(self, text: str):
            """Filter available items based on search."""
            self._update_display()

        def _update_display(self):
            """Update pill displays."""
            available_search_text = self.available_search_input.text().lower()
            selected_search_text = self.selected_search_input.text().lower()

            # Clear layouts
            while self.available_layout.count():
                child = self.available_layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()

            while self.selected_layout.count():
                child = self.selected_layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()

            # Update available (filtered by available search)
            filtered_available = [item for item in self.available_items if available_search_text in item.lower()]
            for item in filtered_available:
                pill = PillWidget(item, "right")
                pill.arrow_btn.clicked.connect(lambda checked, i=item: self._move_to_selected(i))
                self.available_layout.addWidget(pill)

            # Update selected (filtered by selected search)
            filtered_selected = [item for item in self.selected_items if selected_search_text in item.lower()]
            for item in filtered_selected:
                pill = PillWidget(item, "left")
                pill.arrow_btn.clicked.connect(lambda checked, i=item: self._move_to_available(i))
                self.selected_layout.addWidget(pill)

        def _move_to_selected(self, item: str):
            """Move item from available to selected."""
            if item in self.available_items:
                self.available_items.remove(item)
                self.selected_items.append(item)
                self._update_display()

        def _move_to_available(self, item: str):
            """Move item from selected to available."""
            if item in self.selected_items:
                self.selected_items.remove(item)
                self.available_items.append(item)
                self._update_display()

    class TagsSelector(DualListSelector):
        """Tags selector with create functionality."""

        def __init__(self, web_client, parent=None):
            super().__init__("Tags", parent)
            self.web = web_client

            # Add create button below available search
            self.create_button = QtWidgets.QPushButton("Create tag")
            self.create_button.setVisible(False)
            self.create_button.clicked.connect(self._on_create_tag)
            # Insert in the left side layout (after title and available search, before scroll area)
            left_container = self.layout().itemAt(1).layout().itemAt(0).widget()  # Get left container
            left_layout = left_container.layout()
            left_layout.insertWidget(2, self.create_button)  # Insert after label and search box

        def _on_search_changed(self, text: str):
            """Show create button if no matches in available search."""
            search_text = self.available_search_input.text().strip().lower()

            if search_text:
                # Check if any items match
                matches = [item for item in self.all_items if search_text in item.lower()]

                if not matches and search_text:
                    # No matches - show create button
                    self.create_button.setText(f"Create '{self.available_search_input.text().strip()}'")
                    self.create_button.setVisible(True)
                else:
                    self.create_button.setVisible(False)
            else:
                self.create_button.setVisible(False)

            super()._on_search_changed(text)

        def _on_create_tag(self):
            """Create new tag and add to available list (not selected)."""
            tag_name = self.available_search_input.text().strip()
            if not tag_name:
                return

            try:
                # Create tag in binlex-web
                if not self.web.add_tag(tag_name):
                    show_error(f"Failed to create tag: {tag_name}")
                    return

                # Add to all items and available (NOT selected)
                self.all_items.append(tag_name)
                if tag_name not in self.available_items:
                    self.available_items.append(tag_name)

                # Clear search and update
                self.available_search_input.clear()
                self._update_display()

            except Exception as e:
                show_error(f"Failed to create tag: {e}")

    class IndexDialog(QtWidgets.QDialog):
        def __init__(self) -> None:
            super().__init__(None)
            self.setWindowTitle(title)
            self.resize(700, 500)

            layout = QtWidgets.QVBoxLayout(self)

            # Fetch data from web
            from core.config import build_web_client
            web = build_web_client(plugin_config)

            # Fetch available corpora and tags
            try:
                corpora_response = web.search_corpora("")
                # corpora_response is a CorporaCatalog object with .corpora() method
                corpora_items = corpora_response.corpora()  # Returns list of MetadataItem
                available_corpora = [item.name() for item in corpora_items]
            except Exception as e:
                show_error(f"Failed to fetch corpora: {e}")
                available_corpora = []

            try:
                tags_response = web.search_tags("", limit=1000)
                # tags_response is a TagsCatalog object with .tags() method
                tags_items = tags_response.tags()  # Returns list of MetadataItem
                available_tags = [item.name() for item in tags_items]
            except Exception as e:
                show_error(f"Failed to fetch tags: {e}")
                available_tags = []

            # Tab widget
            self.tabs = QtWidgets.QTabWidget(self)

            # Corpora tab
            self.corpora_selector = DualListSelector("Corpora")
            default_corpora = _parse_corpora(plugin_config.default_corpus)
            self.corpora_selector.set_items(available_corpora, default_corpora)
            self.tabs.addTab(self.corpora_selector, "Corpora")

            # Tags tab
            self.tags_selector = TagsSelector(web)
            self.tags_selector.set_items(available_tags, [])
            self.tabs.addTab(self.tags_selector, "Tags")

            layout.addWidget(self.tabs)

            # Index blocks checkbox
            if allow_index_blocks:
                self.index_blocks_checkbox = QtWidgets.QCheckBox("Index Blocks")
                self.index_blocks_checkbox.setChecked(plugin_config.default_index_blocks_with_functions)
                layout.addWidget(self.index_blocks_checkbox)
            else:
                self.index_blocks_checkbox = None

            # Symbol pushing options
            symbol_group = QtWidgets.QGroupBox("Symbol Pushing")
            symbol_layout = QtWidgets.QVBoxLayout()

            self.symbol_none_radio = QtWidgets.QRadioButton("Don't Push Symbols")
            self.symbol_all_radio = QtWidgets.QRadioButton("Push All Symbols")
            self.symbol_prefix_radio = QtWidgets.QRadioButton("Push Symbols Matching Prefix:")

            # Default to "Don't Push Symbols"
            self.symbol_none_radio.setChecked(True)

            # Prefix input (indented and initially disabled)
            prefix_container = QtWidgets.QWidget()
            prefix_layout = QtWidgets.QHBoxLayout(prefix_container)
            prefix_layout.setContentsMargins(30, 0, 0, 0)  # Indent
            self.symbol_prefix_input = QtWidgets.QLineEdit()
            self.symbol_prefix_input.setText("mw::")
            self.symbol_prefix_input.setPlaceholderText("e.g., mw::")
            self.symbol_prefix_input.setEnabled(False)  # Disabled by default
            prefix_layout.addWidget(self.symbol_prefix_input)

            # Add to layout
            symbol_layout.addWidget(self.symbol_none_radio)
            symbol_layout.addWidget(self.symbol_all_radio)
            symbol_layout.addWidget(self.symbol_prefix_radio)
            symbol_layout.addWidget(prefix_container)

            symbol_group.setLayout(symbol_layout)
            layout.addWidget(symbol_group)

            # Connect radio buttons to enable/disable prefix field
            self.symbol_none_radio.toggled.connect(lambda: self.symbol_prefix_input.setEnabled(False))
            self.symbol_all_radio.toggled.connect(lambda: self.symbol_prefix_input.setEnabled(False))
            self.symbol_prefix_radio.toggled.connect(lambda checked: self.symbol_prefix_input.setEnabled(checked))

            # Buttons
            buttons = QtWidgets.QDialogButtonBox(
                QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel,
                self
            )
            buttons.accepted.connect(self.accept)
            buttons.rejected.connect(self.reject)
            layout.addWidget(buttons)

    dialog = IndexDialog()
    result = exec_dialog(dialog)

    if result != QtWidgets.QDialog.Accepted:
        return None

    corpora = dialog.corpora_selector.get_selected()
    if not corpora:
        show_error("At least one corpus must be selected")
        return None

    # Determine symbol push mode
    if dialog.symbol_none_radio.isChecked():
        symbol_push_mode = "none"
        symbol_prefix = ""
    elif dialog.symbol_all_radio.isChecked():
        symbol_push_mode = "all"
        symbol_prefix = ""
    else:  # prefix radio is checked
        symbol_push_mode = "prefix"
        symbol_prefix = dialog.symbol_prefix_input.text().strip()

    return IndexRequest(
        corpora=corpora,
        tags=dialog.tags_selector.get_selected(),
        index_blocks=dialog.index_blocks_checkbox.isChecked() if dialog.index_blocks_checkbox else False,
        symbol_push_mode=symbol_push_mode,
        symbol_prefix=symbol_prefix,
    )


def prompt_search(title: str, plugin_config: PluginConfig) -> SearchRequest | None:
    _, QtCore, _, QtWidgets = import_qt()

    class SearchDialog(QtWidgets.QDialog):
        def __init__(self) -> None:
            super().__init__(None)
            self.setWindowTitle(title)
            self.resize(500, 150)

            layout = QtWidgets.QFormLayout(self)

            # Corpora input
            self.corpora_input = QtWidgets.QLineEdit(self)
            self.corpora_input.setText(plugin_config.default_corpus)
            self.corpora_input.setPlaceholderText("comma-separated corpus names")
            layout.addRow("Corpora:", self.corpora_input)

            # Limit input
            self.limit_input = QtWidgets.QSpinBox(self)
            self.limit_input.setRange(1, 256)
            self.limit_input.setValue(plugin_config.default_compare_limit)
            layout.addRow("Result Limit:", self.limit_input)

            # Buttons
            buttons = QtWidgets.QDialogButtonBox(
                QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel,
                self
            )
            buttons.accepted.connect(self.accept)
            buttons.rejected.connect(self.reject)
            layout.addRow(buttons)

    dialog = SearchDialog()
    result = exec_dialog(dialog)

    if result != QtWidgets.QDialog.Accepted:
        return None

    corpora = _parse_corpora(dialog.corpora_input.text())
    return SearchRequest(corpora=corpora or ["default"], limit=dialog.limit_input.value())


def show_error(message: str, parent=None) -> None:
    del parent
    ida_kernwin.warning(message)


def show_info(message: str, parent=None) -> None:
    del parent
    ida_kernwin.msg(f"[*] {message}\n")
