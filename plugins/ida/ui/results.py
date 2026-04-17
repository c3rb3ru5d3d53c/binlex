from __future__ import annotations

import ida_kernwin
import idaapi

try:
    from qt_compat import exec_dialog, import_qt
except ModuleNotFoundError:  # pragma: no cover - fallback for packaged package layouts
    from ..qt_compat import exec_dialog, import_qt

# Global list to keep references to open dialogs so they don't get garbage collected
_open_dialogs = []


class CorporaPopoverDialog:
    """Interactive dialog for viewing and managing corpora on a search result."""

    def __init__(self, row: dict, web_client, parent=None):
        _, QtCore, _, QtWidgets = import_qt()

        self.row = row
        self.web = web_client
        self.sha256 = row.get("sha256", "")
        self.collection = row.get("collection", "")
        self.address = int(row.get("match_address", 0))

        # Use corpora from row data (populated during search)
        self.current_corpora = list(row.get("corpora", []))
        ida_kernwin.msg(f"[*] CorporaPopover initialized with corpora: {self.current_corpora}\n")

        self.available_corpora = []

        self.dialog = QtWidgets.QDialog(parent)
        self.dialog.setWindowTitle("Manage Corpora")
        self.dialog.resize(700, 400)

        layout = QtWidgets.QVBoxLayout(self.dialog)

        # Info label
        info_text = f"Entity: {hex(self.address)} | SHA256: {self.sha256[:16]}..."
        info_label = QtWidgets.QLabel(info_text, self.dialog)
        layout.addWidget(info_label)

        # Dual-list layout with pills
        lists_layout = QtWidgets.QHBoxLayout()

        # Available corpora (left)
        available_group = QtWidgets.QGroupBox("Available", self.dialog)
        available_layout = QtWidgets.QVBoxLayout(available_group)

        available_search_layout = QtWidgets.QHBoxLayout()
        available_search_label = QtWidgets.QLabel("Search:", self.dialog)
        self.available_search = QtWidgets.QLineEdit(self.dialog)
        self.available_search.setPlaceholderText("Search or create corpus...")
        available_search_layout.addWidget(available_search_label)
        available_search_layout.addWidget(self.available_search)
        available_layout.addLayout(available_search_layout)

        self.available_scroll = QtWidgets.QScrollArea(self.dialog)
        self.available_scroll.setWidgetResizable(True)
        self.available_container = QtWidgets.QWidget()
        self.available_layout = QtWidgets.QVBoxLayout(self.available_container)
        self.available_layout.setAlignment(QtCore.Qt.AlignTop)
        self.available_layout.setSpacing(5)
        self.available_container.setLayout(self.available_layout)
        self.available_scroll.setWidget(self.available_container)
        available_layout.addWidget(self.available_scroll)

        self.create_button = QtWidgets.QPushButton("Create", self.dialog)
        self.create_button.clicked.connect(self._create_corpus)
        self.create_button.setVisible(False)
        available_layout.addWidget(self.create_button)

        lists_layout.addWidget(available_group)

        # Assigned corpora (right)
        assigned_group = QtWidgets.QGroupBox("Assigned", self.dialog)
        assigned_layout = QtWidgets.QVBoxLayout(assigned_group)

        assigned_search_layout = QtWidgets.QHBoxLayout()
        assigned_search_label = QtWidgets.QLabel("Search:", self.dialog)
        self.assigned_search = QtWidgets.QLineEdit(self.dialog)
        self.assigned_search.setPlaceholderText("Filter assigned...")
        assigned_search_layout.addWidget(assigned_search_label)
        assigned_search_layout.addWidget(self.assigned_search)
        assigned_layout.addLayout(assigned_search_layout)

        self.assigned_scroll = QtWidgets.QScrollArea(self.dialog)
        self.assigned_scroll.setWidgetResizable(True)
        self.assigned_container = QtWidgets.QWidget()
        self.assigned_layout = QtWidgets.QVBoxLayout(self.assigned_container)
        self.assigned_layout.setAlignment(QtCore.Qt.AlignTop)
        self.assigned_layout.setSpacing(5)
        self.assigned_container.setLayout(self.assigned_layout)
        self.assigned_scroll.setWidget(self.assigned_container)
        assigned_layout.addWidget(self.assigned_scroll)

        lists_layout.addWidget(assigned_group)

        layout.addLayout(lists_layout)

        # Close button
        close_button = QtWidgets.QPushButton("Close", self.dialog)
        close_button.clicked.connect(self.dialog.accept)
        layout.addWidget(close_button)

        # Connect search
        self.available_search.textChanged.connect(self._search_corpora)
        self.assigned_search.textChanged.connect(self._filter_assigned)

        # Initial load
        self._load_corpora()

    def _create_flow_layout(self):
        """Create a flow layout for pills."""
        _, QtCore, _, QtWidgets = import_qt()

        class FlowLayout(QtWidgets.QLayout):
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

        return FlowLayout(spacing=8)

    def _create_pill(self, text: str, arrow_direction: str, callback):
        """Create a pill widget with arrow button."""
        _, QtCore, _, QtWidgets = import_qt()

        pill = QtWidgets.QWidget()
        layout = QtWidgets.QHBoxLayout(pill)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(4)

        if arrow_direction == "left":
            arrow_btn = QtWidgets.QPushButton("←")
            arrow_btn.setFixedSize(20, 20)
            arrow_btn.clicked.connect(lambda: callback(text))
            layout.addWidget(arrow_btn)

        label = QtWidgets.QLabel(text)
        layout.addWidget(label)

        if arrow_direction == "right":
            arrow_btn = QtWidgets.QPushButton("→")
            arrow_btn.setFixedSize(20, 20)
            arrow_btn.clicked.connect(lambda: callback(text))
            layout.addWidget(arrow_btn)

        pill.setStyleSheet("""
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

        return pill

    def _load_corpora(self):
        """Load corpora from server."""
        ida_kernwin.msg(f"[*] _load_corpora: current_corpora = {self.current_corpora}\n")
        try:
            response = self.web.search_corpora("")
            corpora_items = response.corpora()
            all_corpora = [item.name() for item in corpora_items]
            self.available_corpora = [c for c in all_corpora if c not in self.current_corpora]
            ida_kernwin.msg(f"[*] All corpora: {all_corpora}, Available: {self.available_corpora}\n")
        except Exception as e:
            ida_kernwin.msg(f"[!] Exception: {e}\n")
            self.available_corpora = []
        self._update_displays()

    def _search_corpora(self, query: str):
        """Filter available corpora by search query."""
        if not query:
            self._update_display_list(self.available_layout, self.available_corpora, "right", self._move_to_assigned)
            self.create_button.setVisible(False)
            return

        try:
            response = self.web.search_corpora(query)
            corpora_items = response.corpora()
            available = [item.name() for item in corpora_items if item.name() not in self.current_corpora]

            # Show create button if query doesn't match existing
            exact_match = any(item.name() == query for item in corpora_items)
            self.create_button.setVisible(bool(query) and not exact_match)

            self._update_display_list(self.available_layout, available, "right", self._move_to_assigned)
        except Exception:
            self._update_display_list(self.available_layout, [], "right", self._move_to_assigned)

    def _filter_assigned(self, query: str):
        """Filter assigned corpora by search query."""
        if not query:
            self._update_display_list(self.assigned_layout, self.current_corpora, "left", self._move_to_available)
            return

        filtered = [c for c in self.current_corpora if query.lower() in c.lower()]
        self._update_display_list(self.assigned_layout, filtered, "left", self._move_to_available)

    def _update_displays(self):
        """Update both pill displays."""
        ida_kernwin.msg(f"[*] _update_displays: available={len(self.available_corpora)}, assigned={len(self.current_corpora)}\n")
        ida_kernwin.msg(f"[*] Assigned corpora: {self.current_corpora}\n")
        self._update_display_list(self.available_layout, self.available_corpora, "right", self._move_to_assigned)
        self._update_display_list(self.assigned_layout, self.current_corpora, "left", self._move_to_available)

    def _update_display_list(self, flow_layout, items, arrow_direction, callback):
        """Update a flow layout with pills."""
        ida_kernwin.msg(f"[*] _update_display_list: {len(items)} items, direction={arrow_direction}\n")
        # Clear existing pills
        while flow_layout.count():
            item = flow_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Add new pills
        for item_text in items:
            ida_kernwin.msg(f"[*] Creating pill: '{item_text}' with arrow {arrow_direction}\n")
            pill = self._create_pill(item_text, arrow_direction, callback)
            flow_layout.addWidget(pill)

    def _move_to_assigned(self, corpus: str):
        """Move corpus from available to assigned."""
        try:
            if not self.web.add_entity_corpus(self.sha256, self.collection, self.address, corpus):
                ida_kernwin.msg(f"[!] Failed to assign corpus: {corpus}\n")
                return

            if corpus in self.available_corpora:
                self.available_corpora.remove(corpus)
            self.current_corpora.append(corpus)
            self.row["corpora"] = self.current_corpora
            ida_kernwin.msg(f"[*] Assigned corpus: {corpus}\n")
            self._update_displays()
        except Exception as e:
            ida_kernwin.msg(f"[!] Error assigning corpus: {e}\n")

    def _move_to_available(self, corpus: str):
        """Move corpus from assigned back to available."""
        try:
            if not self.web.remove_entity_corpus(self.sha256, self.collection, self.address, corpus):
                ida_kernwin.msg(f"[!] Failed to unassign corpus: {corpus}\n")
                return

            if corpus in self.current_corpora:
                self.current_corpora.remove(corpus)
            if corpus not in self.available_corpora:
                self.available_corpora.append(corpus)
            self.row["corpora"] = self.current_corpora
            ida_kernwin.msg(f"[*] Unassigned corpus: {corpus}\n")
            self._update_displays()
        except Exception as e:
            ida_kernwin.msg(f"[!] Error unassigning corpus: {e}\n")

    def _create_corpus(self):
        """Create a new corpus."""
        corpus_name = self.available_search.text().strip()
        if not corpus_name:
            return

        try:
            if not self.web.add_corpus(corpus_name):
                ida_kernwin.msg(f"[!] Failed to create corpus: {corpus_name}\n")
                return

            self.available_corpora.append(corpus_name)
            self.available_search.clear()
            self._update_displays()
            ida_kernwin.msg(f"[*] Created corpus: {corpus_name}\n")
        except Exception as e:
            ida_kernwin.msg(f"[!] Error creating corpus: {e}\n")

    def show(self):
        exec_dialog(self.dialog)


class TagsPopoverDialog:
    """Interactive dialog for viewing and managing tags on a search result."""

    def __init__(self, row: dict, web_client, parent=None):
        _, QtCore, _, QtWidgets = import_qt()

        self.row = row
        self.web = web_client
        self.sha256 = row.get("sha256", "")
        self.collection = row.get("collection", "")
        self.address = int(row.get("match_address", 0))
        self.current_tags = list(row.get("tags", []))
        self.available_tags = []

        self.dialog = QtWidgets.QDialog(parent)
        self.dialog.setWindowTitle("Manage Tags")
        self.dialog.resize(700, 400)

        layout = QtWidgets.QVBoxLayout(self.dialog)

        # Info label
        info_text = f"Entity: {hex(self.address)} | SHA256: {self.sha256[:16]}..."
        info_label = QtWidgets.QLabel(info_text, self.dialog)
        layout.addWidget(info_label)

        # Dual-list layout with pills
        lists_layout = QtWidgets.QHBoxLayout()

        # Available tags (left)
        available_group = QtWidgets.QGroupBox("Available", self.dialog)
        available_layout = QtWidgets.QVBoxLayout(available_group)

        available_search_layout = QtWidgets.QHBoxLayout()
        available_search_label = QtWidgets.QLabel("Search:", self.dialog)
        self.available_search = QtWidgets.QLineEdit(self.dialog)
        self.available_search.setPlaceholderText("Search or create tag...")
        available_search_layout.addWidget(available_search_label)
        available_search_layout.addWidget(self.available_search)
        available_layout.addLayout(available_search_layout)

        self.available_scroll = QtWidgets.QScrollArea(self.dialog)
        self.available_scroll.setWidgetResizable(True)
        self.available_container = QtWidgets.QWidget()
        self.available_layout = QtWidgets.QVBoxLayout(self.available_container)
        self.available_layout.setAlignment(QtCore.Qt.AlignTop)
        self.available_layout.setSpacing(5)
        self.available_container.setLayout(self.available_layout)
        self.available_scroll.setWidget(self.available_container)
        available_layout.addWidget(self.available_scroll)

        self.create_button = QtWidgets.QPushButton("Create", self.dialog)
        self.create_button.clicked.connect(self._create_tag)
        self.create_button.setVisible(False)
        available_layout.addWidget(self.create_button)

        lists_layout.addWidget(available_group)

        # Assigned tags (right)
        assigned_group = QtWidgets.QGroupBox("Assigned", self.dialog)
        assigned_layout = QtWidgets.QVBoxLayout(assigned_group)

        assigned_search_layout = QtWidgets.QHBoxLayout()
        assigned_search_label = QtWidgets.QLabel("Search:", self.dialog)
        self.assigned_search = QtWidgets.QLineEdit(self.dialog)
        self.assigned_search.setPlaceholderText("Filter assigned...")
        assigned_search_layout.addWidget(assigned_search_label)
        assigned_search_layout.addWidget(self.assigned_search)
        assigned_layout.addLayout(assigned_search_layout)

        self.assigned_scroll = QtWidgets.QScrollArea(self.dialog)
        self.assigned_scroll.setWidgetResizable(True)
        self.assigned_container = QtWidgets.QWidget()
        self.assigned_layout = QtWidgets.QVBoxLayout(self.assigned_container)
        self.assigned_layout.setAlignment(QtCore.Qt.AlignTop)
        self.assigned_layout.setSpacing(5)
        self.assigned_container.setLayout(self.assigned_layout)
        self.assigned_scroll.setWidget(self.assigned_container)
        assigned_layout.addWidget(self.assigned_scroll)

        lists_layout.addWidget(assigned_group)

        layout.addLayout(lists_layout)

        # Close button
        close_button = QtWidgets.QPushButton("Close", self.dialog)
        close_button.clicked.connect(self.dialog.accept)
        layout.addWidget(close_button)

        # Connect search
        self.available_search.textChanged.connect(self._search_tags)
        self.assigned_search.textChanged.connect(self._filter_assigned)

        # Initial load
        self._load_tags()

    def _create_flow_layout(self):
        """Create a flow layout for pills."""
        _, QtCore, _, QtWidgets = import_qt()

        class FlowLayout(QtWidgets.QLayout):
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

        return FlowLayout(spacing=8)

    def _create_pill(self, text: str, arrow_direction: str, callback):
        """Create a pill widget with arrow button."""
        _, QtCore, _, QtWidgets = import_qt()

        pill = QtWidgets.QWidget()
        layout = QtWidgets.QHBoxLayout(pill)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(4)

        if arrow_direction == "left":
            arrow_btn = QtWidgets.QPushButton("←")
            arrow_btn.setFixedSize(20, 20)
            arrow_btn.clicked.connect(lambda: callback(text))
            layout.addWidget(arrow_btn)

        label = QtWidgets.QLabel(text)
        layout.addWidget(label)

        if arrow_direction == "right":
            arrow_btn = QtWidgets.QPushButton("→")
            arrow_btn.setFixedSize(20, 20)
            arrow_btn.clicked.connect(lambda: callback(text))
            layout.addWidget(arrow_btn)

        pill.setStyleSheet("""
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

        return pill

    def _load_tags(self):
        """Load tags from server."""
        try:
            response = self.web.search_tags("", limit=100)
            tags_items = response.tags()
            all_tags = [item.name() for item in tags_items]
            self.available_tags = [t for t in all_tags if t not in self.current_tags]
        except Exception:
            self.available_tags = []
        self._update_displays()

    def _search_tags(self, query: str):
        """Filter available tags by search query."""
        if not query:
            self._update_display_list(self.available_layout, self.available_tags, "right", self._move_to_assigned)
            self.create_button.setVisible(False)
            return

        try:
            response = self.web.search_tags(query, limit=100)
            tags_items = response.tags()
            available = [item.name() for item in tags_items if item.name() not in self.current_tags]

            # Show create button if query doesn't match existing
            exact_match = any(item.name() == query for item in tags_items)
            self.create_button.setVisible(bool(query) and not exact_match)

            self._update_display_list(self.available_layout, available, "right", self._move_to_assigned)
        except Exception:
            self._update_display_list(self.available_layout, [], "right", self._move_to_assigned)

    def _filter_assigned(self, query: str):
        """Filter assigned tags by search query."""
        if not query:
            self._update_display_list(self.assigned_layout, self.current_tags, "left", self._move_to_available)
            return

        filtered = [t for t in self.current_tags if query.lower() in t.lower()]
        self._update_display_list(self.assigned_layout, filtered, "left", self._move_to_available)

    def _update_displays(self):
        """Update both pill displays."""
        self._update_display_list(self.available_layout, self.available_tags, "right", self._move_to_assigned)
        self._update_display_list(self.assigned_layout, self.current_tags, "left", self._move_to_available)

    def _update_display_list(self, flow_layout, items, arrow_direction, callback):
        """Update a flow layout with pills."""
        ida_kernwin.msg(f"[*] _update_display_list: {len(items)} items, direction={arrow_direction}\n")
        # Clear existing pills
        while flow_layout.count():
            item = flow_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Add new pills
        for item_text in items:
            ida_kernwin.msg(f"[*] Creating pill: '{item_text}' with arrow {arrow_direction}\n")
            pill = self._create_pill(item_text, arrow_direction, callback)
            flow_layout.addWidget(pill)

    def _move_to_assigned(self, tag: str):
        """Move tag from available to assigned."""
        try:
            if not self.web.add_entity_tag(self.sha256, self.collection, self.address, tag):
                ida_kernwin.msg(f"[!] Failed to assign tag: {tag}\n")
                return

            if tag in self.available_tags:
                self.available_tags.remove(tag)
            self.current_tags.append(tag)
            self.row["tags"] = self.current_tags
            ida_kernwin.msg(f"[*] Assigned tag: {tag}\n")
            self._update_displays()
        except Exception as e:
            ida_kernwin.msg(f"[!] Error assigning tag: {e}\n")

    def _move_to_available(self, tag: str):
        """Move tag from assigned back to available."""
        try:
            if not self.web.remove_entity_tag(self.sha256, self.collection, self.address, tag):
                ida_kernwin.msg(f"[!] Failed to unassign tag: {tag}\n")
                return

            if tag in self.current_tags:
                self.current_tags.remove(tag)
            if tag not in self.available_tags:
                self.available_tags.append(tag)
            self.row["tags"] = self.current_tags
            ida_kernwin.msg(f"[*] Unassigned tag: {tag}\n")
            self._update_displays()
        except Exception as e:
            ida_kernwin.msg(f"[!] Error unassigning tag: {e}\n")

    def _create_tag(self):
        """Create a new tag."""
        tag_name = self.available_search.text().strip()
        if not tag_name:
            return

        try:
            if not self.web.add_tag(tag_name):
                ida_kernwin.msg(f"[!] Failed to create tag: {tag_name}\n")
                return

            self.available_tags.append(tag_name)
            self.available_search.clear()
            self._update_displays()
            ida_kernwin.msg(f"[*] Created tag: {tag_name}\n")
        except Exception as e:
            ida_kernwin.msg(f"[!] Error creating tag: {e}\n")

    def show(self):
        exec_dialog(self.dialog)


class CommentsPopoverDialog:
    """Interactive dialog for viewing and adding comments on a search result."""

    def __init__(self, row: dict, web_client, parent=None):
        _, QtCore, _, QtWidgets = import_qt()

        self.row = row
        self.web = web_client
        self.sha256 = row.get("sha256", "")
        self.collection = row.get("collection", "")
        self.address = int(row.get("match_address", 0))
        self.current_comments = list(row.get("comments", []))

        self.dialog = QtWidgets.QDialog(parent)
        self.dialog.setWindowTitle("Manage Comments")
        self.dialog.resize(600, 500)

        layout = QtWidgets.QVBoxLayout(self.dialog)

        # Info label
        info_text = f"Entity: {hex(self.address)} | SHA256: {self.sha256[:16]}..."
        info_label = QtWidgets.QLabel(info_text, self.dialog)
        layout.addWidget(info_label)

        # Comments display
        comments_group = QtWidgets.QGroupBox("Comments", self.dialog)
        comments_layout = QtWidgets.QVBoxLayout(comments_group)

        self.comments_display = QtWidgets.QTextEdit(self.dialog)
        self.comments_display.setReadOnly(True)
        self._update_comments_display()
        comments_layout.addWidget(self.comments_display)

        layout.addWidget(comments_group)

        # Add comment section
        add_group = QtWidgets.QGroupBox("Add Comment", self.dialog)
        add_layout = QtWidgets.QVBoxLayout(add_group)

        self.comment_input = QtWidgets.QTextEdit(self.dialog)
        self.comment_input.setPlaceholderText("Enter your comment...")
        self.comment_input.setMaximumHeight(100)
        add_layout.addWidget(self.comment_input)

        add_button = QtWidgets.QPushButton("Add Comment", self.dialog)
        add_button.clicked.connect(self._add_comment)
        add_layout.addWidget(add_button)

        layout.addWidget(add_group)

        # Close button
        close_button = QtWidgets.QPushButton("Close", self.dialog)
        close_button.clicked.connect(self.dialog.accept)
        layout.addWidget(close_button)

    def _update_comments_display(self):
        if not self.current_comments:
            self.comments_display.setPlainText("No comments yet.")
            return

        lines = []
        for comment in self.current_comments:
            username = comment.get("username", "unknown")
            timestamp = comment.get("timestamp", "")
            body = comment.get("comment", "")
            lines.append(f"[{username}] {timestamp}")
            lines.append(body)
            lines.append("-" * 60)

        self.comments_display.setPlainText("\n".join(lines))

    def _add_comment(self):
        comment_text = self.comment_input.toPlainText().strip()
        if not comment_text:
            return

        try:
            if not self.web.add_entity_comment(self.sha256, self.collection, self.address, comment_text):
                ida_kernwin.msg(f"[!] Failed to add comment\n")
                return

            # Refresh comments from server
            response = self.web.entity_comments(self.sha256, self.collection, self.address)
            comments = response.items()
            self.current_comments = []
            for comment in comments:
                user = comment.user()
                self.current_comments.append({
                    "username": user.username(),
                    "comment": comment.body(),
                    "timestamp": str(comment.timestamp()),
                })

            self.row["comments"] = self.current_comments
            self._update_comments_display()
            self.comment_input.clear()
            ida_kernwin.msg(f"[*] Comment added\n")
        except Exception as e:
            ida_kernwin.msg(f"[!] Error adding comment: {e}\n")

    def show(self):
        exec_dialog(self.dialog)


class SymbolSelectorDialog:
    """Dialog for selecting a symbol to apply as a function name."""

    def __init__(self, row: dict, web_client, parent=None):
        _, QtCore, _, QtWidgets = import_qt()

        self.row = row
        self.web = web_client
        self.sha256 = row.get("sha256", "")
        self.collection = row.get("collection", "")
        self.address = int(row.get("match_address", 0))
        self.symbols = row.get("symbols", [])
        self.selected_symbol = None
        self.available_symbols = []
        self.assigned_symbols = []

        self.dialog = QtWidgets.QDialog(parent)
        self.dialog.setWindowTitle("Manage Symbols")
        self.dialog.resize(700, 400)

        layout = QtWidgets.QVBoxLayout(self.dialog)

        # Info label
        info_text = (
            f"Match: {hex(self.address)} | "
            f"Score: {float(row.get('score', 0)):.6f} | "
            f"Corpus: {', '.join(row.get('corpora', []))}"
        )
        info_label = QtWidgets.QLabel(info_text, self.dialog)
        layout.addWidget(info_label)

        # Dual-list layout with pills
        lists_layout = QtWidgets.QHBoxLayout()

        # Available symbols (left)
        available_group = QtWidgets.QGroupBox("Available", self.dialog)
        available_layout = QtWidgets.QVBoxLayout(available_group)

        available_search_layout = QtWidgets.QHBoxLayout()
        available_search_label = QtWidgets.QLabel("Search:", self.dialog)
        self.available_search = QtWidgets.QLineEdit(self.dialog)
        self.available_search.setPlaceholderText("Search or create symbol...")
        available_search_layout.addWidget(available_search_label)
        available_search_layout.addWidget(self.available_search)
        available_layout.addLayout(available_search_layout)

        self.available_scroll = QtWidgets.QScrollArea(self.dialog)
        self.available_scroll.setWidgetResizable(True)
        self.available_container = QtWidgets.QWidget()
        self.available_layout = QtWidgets.QVBoxLayout(self.available_container)
        self.available_layout.setAlignment(QtCore.Qt.AlignTop)
        self.available_layout.setSpacing(5)
        self.available_container.setLayout(self.available_layout)
        self.available_scroll.setWidget(self.available_container)
        available_layout.addWidget(self.available_scroll)

        self.create_button = QtWidgets.QPushButton("Create", self.dialog)
        self.create_button.clicked.connect(self._create_symbol)
        self.create_button.setVisible(False)
        available_layout.addWidget(self.create_button)

        lists_layout.addWidget(available_group)

        # Assigned symbols (right) - for applying to function
        assigned_group = QtWidgets.QGroupBox("Assigned", self.dialog)
        assigned_layout = QtWidgets.QVBoxLayout(assigned_group)

        assigned_search_layout = QtWidgets.QHBoxLayout()
        assigned_search_label = QtWidgets.QLabel("Search:", self.dialog)
        self.assigned_search = QtWidgets.QLineEdit(self.dialog)
        self.assigned_search.setPlaceholderText("Filter selected...")
        assigned_search_layout.addWidget(assigned_search_label)
        assigned_search_layout.addWidget(self.assigned_search)
        assigned_layout.addLayout(assigned_search_layout)

        self.assigned_scroll = QtWidgets.QScrollArea(self.dialog)
        self.assigned_scroll.setWidgetResizable(True)
        self.assigned_container = QtWidgets.QWidget()
        self.assigned_layout = QtWidgets.QVBoxLayout(self.assigned_container)
        self.assigned_layout.setAlignment(QtCore.Qt.AlignTop)
        self.assigned_layout.setSpacing(5)
        self.assigned_container.setLayout(self.assigned_layout)
        self.assigned_scroll.setWidget(self.assigned_container)
        assigned_layout.addWidget(self.assigned_scroll)

        self.apply_button = QtWidgets.QPushButton("Apply Selected Symbol", self.dialog)
        self.apply_button.clicked.connect(self._apply_selected)
        assigned_layout.addWidget(self.apply_button)

        lists_layout.addWidget(assigned_group)

        layout.addLayout(lists_layout)

        # Close button
        close_button = QtWidgets.QPushButton("Close", self.dialog)
        close_button.clicked.connect(self.dialog.reject)
        layout.addWidget(close_button)

        # Connect search
        self.available_search.textChanged.connect(self._search_symbols)
        self.assigned_search.textChanged.connect(self._filter_assigned)

        # Initial load
        self._load_symbols()

    def _create_flow_layout(self):
        """Create a flow layout for pills."""
        _, QtCore, _, QtWidgets = import_qt()

        class FlowLayout(QtWidgets.QLayout):
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

        return FlowLayout(spacing=8)

    def _create_pill(self, text: str, arrow_direction: str, callback):
        """Create a pill widget with arrow button."""
        _, QtCore, _, QtWidgets = import_qt()

        pill = QtWidgets.QWidget()
        layout = QtWidgets.QHBoxLayout(pill)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(4)

        if arrow_direction == "left":
            arrow_btn = QtWidgets.QPushButton("←")
            arrow_btn.setFixedSize(20, 20)
            arrow_btn.clicked.connect(lambda: callback(text))
            layout.addWidget(arrow_btn)

        label = QtWidgets.QLabel(text)
        layout.addWidget(label)

        if arrow_direction == "right":
            arrow_btn = QtWidgets.QPushButton("→")
            arrow_btn.setFixedSize(20, 20)
            arrow_btn.clicked.connect(lambda: callback(text))
            layout.addWidget(arrow_btn)

        pill.setStyleSheet("""
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

        return pill

    def _load_symbols(self):
        """Load symbols from server."""
        # Start with symbols already on this entity
        self.available_symbols = list(self.symbols)
        self.assigned_symbols = []
        self._update_displays()

    def _search_symbols(self, query: str):
        """Live search for symbols on server."""
        if not query:
            self._update_display_list(self.available_layout, self.available_symbols, "right", self._move_to_assigned)
            self.create_button.setVisible(False)
            return

        try:
            # Do live search against server for symbols
            response = self.web.search_collection_symbols(
                self.collection,
                query,
                limit=100
            )
            symbols_items = response.symbols()
            available = [item.name() for item in symbols_items if item.name() not in self.assigned_symbols]

            # Show create button if query doesn't match existing
            exact_match = any(item.name() == query for item in symbols_items)
            self.create_button.setVisible(bool(query) and not exact_match)

            self._update_display_list(self.available_layout, available, "right", self._move_to_assigned)
        except Exception as e:
            ida_kernwin.msg(f"[!] Symbol search error: {e}\n")
            # Fallback to local filtering
            filtered = [s for s in self.available_symbols if query.lower() in s.lower()]
            exact_match = query in self.available_symbols
            self.create_button.setVisible(bool(query) and not exact_match)
            self._update_display_list(self.available_layout, filtered, "right", self._move_to_assigned)

    def _filter_assigned(self, query: str):
        """Filter assigned symbols by search query."""
        if not query:
            self._update_display_list(self.assigned_layout, self.assigned_symbols, "left", self._move_to_available)
            return

        # Filter assigned symbols
        filtered = [s for s in self.assigned_symbols if query.lower() in s.lower()]
        self._update_display_list(self.assigned_layout, filtered, "left", self._move_to_available)

    def _update_displays(self):
        """Update both pill displays."""
        self._update_display_list(self.available_layout, self.available_symbols, "right", self._move_to_assigned)
        self._update_display_list(self.assigned_layout, self.assigned_symbols, "left", self._move_to_available)

    def _update_display_list(self, flow_layout, items, arrow_direction, callback):
        """Update a flow layout with pills."""
        ida_kernwin.msg(f"[*] _update_display_list: {len(items)} items, direction={arrow_direction}\n")
        # Clear existing pills
        while flow_layout.count():
            item = flow_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Add new pills
        for item_text in items:
            ida_kernwin.msg(f"[*] Creating pill: '{item_text}' with arrow {arrow_direction}\n")
            pill = self._create_pill(item_text, arrow_direction, callback)
            flow_layout.addWidget(pill)

    def _move_to_assigned(self, symbol: str):
        """Move symbol from available to assigned."""
        if symbol in self.available_symbols:
            self.available_symbols.remove(symbol)
            # Replace any existing assigned symbol (only one can be selected)
            self.assigned_symbols = [symbol]
            self._update_displays()

    def _move_to_available(self, symbol: str):
        """Move symbol from assigned back to available."""
        if symbol in self.assigned_symbols:
            self.assigned_symbols.remove(symbol)
            if symbol not in self.available_symbols:
                self.available_symbols.append(symbol)
            self._update_displays()

    def _create_symbol(self):
        """Create a new symbol."""
        symbol_name = self.available_search.text().strip()
        if not symbol_name:
            return

        try:
            # Add the symbol to this entity
            if not self.web.add_collection_symbol(
                self.sha256, self.collection,
                self.row.get("architecture", ""),
                self.address, symbol_name
            ):
                ida_kernwin.msg(f"[!] Failed to create symbol: {symbol_name}\n")
                return

            self.symbols.append(symbol_name)
            self.available_symbols.append(symbol_name)
            self.row["symbols"] = self.symbols
            self.available_search.clear()
            self._update_displays()
            ida_kernwin.msg(f"[*] Created symbol: {symbol_name}\n")
        except Exception as e:
            ida_kernwin.msg(f"[!] Error creating symbol: {e}\n")

    def _apply_selected(self):
        """Apply the selected symbol."""
        if self.assigned_symbols:
            self.selected_symbol = self.assigned_symbols[0]
            self.dialog.accept()

    def show(self) -> str | None:
        if exec_dialog(self.dialog):
            return self.selected_symbol
        return None


def _symbol_display(symbols: list[str]) -> str:
    """Format symbol count for display: '+' for none, '+1' for one, '+2' for two, etc."""
    count = len(symbols)
    if count == 0:
        return "+"
    return f"+{count}"


def _corpora_display(corpora: list[str]) -> str:
    """Format corpora count for display: '+' for none, '+1' for one, '+2' for two, etc."""
    count = len(corpora)
    if count == 0:
        return "+"
    return f"+{count}"


def _tags_display(tags: list[str]) -> str:
    """Format tag count for display: '+' for none, '+1' for one, '+2' for two, etc."""
    count = len(tags)
    if count == 0:
        return "+"
    return f"+{count}"


def _comments_display(comments: list[dict]) -> str:
    """Format comment count for display: '+' for none, '+1' for one, '+2' for two, etc."""
    count = len(comments)
    if count == 0:
        return "+"
    return f"+{count}"


def _format_row(index: int, row: dict) -> str:
    symbols_display = _symbol_display(row.get("symbols", []))
    tags_display = _tags_display(row.get("tags", []))
    comments_display = _comments_display(row.get("comments", []))
    return (
        f"[{index}] "
        f"local={hex(int(row['local_address']))} "
        f"name='{row['local_name']}' "
        f"score={float(row['score']):.6f} "
        f"match={hex(int(row['match_address']))} "
        f"symbols={symbols_display} "
        f"corpus='{row['corpus']}' "
        f"sha256={row['sha256']} "
        f"tags={tags_display} "
        f"comments={comments_display}"
    )


def _copy_rows_to_clipboard(rows: list[dict]) -> bool:
    try:
        _, _, QtGui, _ = import_qt()
    except Exception:
        return False

    header = [
        "Local Name",
        "Local Address",
        "Symbols",
        "Match Address",
        "Score",
        "Corpus",
        "SHA256",
        "Tags",
        "Comments",
        "Architecture",
    ]
    lines = ["\t".join(header)]
    for row in rows:
        tags = ", ".join(row.get("tags", []))
        comments_count = str(len(row.get("comments", [])))
        symbols = "; ".join(row.get("symbols", []))
        lines.append(
            "\t".join(
                [
                    str(row["local_name"]),
                    hex(int(row["local_address"])),
                    symbols,
                    hex(int(row["match_address"])),
                    f"{float(row['score']):.6f}",
                    str(row["corpus"]),
                    str(row["sha256"]),
                    tags,
                    comments_count,
                    str(row.get("architecture", "")),
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
    web_client,
) -> None:
    """Show results in a dockable window"""
    if not rows:
        ida_kernwin.msg(f"[*] {title}: no results\n")
        return

    try:
        # Try to use the dockable window implementation
        from .dockable_results import show_results_dockable
        show_results_dockable(
            title,
            rows,
            apply_one=apply_one,
            apply_many=apply_many,
            jump_local=jump_local,
            web_client=web_client,
        )
    except Exception as e:
        ida_kernwin.msg(f"[!] Failed to create dockable window: {e}\n")
        # Fall back to the simple dialog
        _show_results_fallback(
            title,
            rows,
            apply_one=apply_one,
            apply_many=apply_many,
            jump_local=jump_local,
        )


