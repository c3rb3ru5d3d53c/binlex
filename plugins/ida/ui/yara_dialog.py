"""Dockable YARA pattern creator widget for IDA Pro"""
from __future__ import annotations

import ida_kernwin
import ida_ua
import idaapi

try:
    from qt_compat import import_qt
except ModuleNotFoundError:
    from ..qt_compat import import_qt

try:
    from core.yara_creator import YaraPatternGenerator
except (ModuleNotFoundError, ImportError):
    from ..core.yara_creator import YaraPatternGenerator


class YaraCreatorForm(idaapi.PluginForm):
    """Dockable form for YARA pattern creation"""

    def __init__(self, start_ea: int = 0, end_ea: int = 0, controller=None):
        super(YaraCreatorForm, self).__init__()
        self._start_ea = start_ea
        self._end_ea = end_ea
        self._widget = None
        self._form = None
        self._controller = controller

    def OnCreate(self, form):
        """Called when the widget is created"""
        try:
            self._form = self.FormToPySideWidget(form)
        except Exception:
            self._form = self.FormToPyQtWidget(form)

        # Create widget (will show placeholder if no valid selection)
        self._widget = YaraPatternWidget(
            self._start_ea,
            self._end_ea,
            parent=self._form
        )

        _, QtCore, _, QtWidgets = import_qt()
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self._widget.widget)
        self._form.setLayout(layout)

    def OnClose(self, form):
        """Called when the widget is closed"""
        self._widget = None
        # Clear controller's reference when closed
        if self._controller is not None:
            self._controller.yara_creator_form = None

    def Show(self):
        """Show the dockable widget"""
        return idaapi.PluginForm.Show(
            self,
            "Binlex YARA Pattern",
            options=idaapi.PluginForm.WOPN_RESTORE | idaapi.PluginForm.WCLS_SAVE
        )

    def update_selection(self, start_ea: int, end_ea: int):
        """Update the form with a new selection"""
        self._start_ea = start_ea
        self._end_ea = end_ea
        if self._widget is not None:
            self._widget.update_selection(start_ea, end_ea)


class YaraPatternWidget:
    """The actual YARA pattern creator widget with instruction table and pattern display"""

    def __init__(self, start_ea: int = 0, end_ea: int = 0, parent=None):
        _, QtCore, QtGui, QtWidgets = import_qt()

        self.widget = QtWidgets.QWidget(parent)

        # Store widget references for updating highlight state
        self.mnemonic_widgets = []
        self.operand_widgets = []

        # Check if we have a valid selection
        if start_ea > 0 and end_ea > start_ea:
            self.generator = YaraPatternGenerator(start_ea, end_ea)
            self._populate_ui()
            self._update_pattern()
        else:
            # Show placeholder when no selection
            self.generator = None
            self._show_placeholder()

    def _show_placeholder(self):
        """Show placeholder message when no selection is loaded"""
        _, QtCore, QtGui, QtWidgets = import_qt()

        layout = QtWidgets.QVBoxLayout(self.widget)
        label = QtWidgets.QLabel("Select instructions in IDA and use\nBinlex → Create → YARA Pattern")
        label.setAlignment(QtCore.Qt.AlignCenter)
        font = label.font()
        font.setPointSize(12)
        label.setFont(font)
        layout.addWidget(label)

    def update_selection(self, start_ea: int, end_ea: int):
        """Update the widget with a new instruction selection"""
        # Create new generator with new selection
        self.generator = YaraPatternGenerator(start_ea, end_ea)

        # Clear widget reference lists
        self.mnemonic_widgets = []
        self.operand_widgets = []

        # Clear old layout
        _, QtCore, QtGui, QtWidgets = import_qt()
        old_layout = self.widget.layout()
        if old_layout is not None:
            while old_layout.count():
                item = old_layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
            QtWidgets.QWidget().setLayout(old_layout)  # Reparent to delete

        # Rebuild UI with new data
        self._populate_ui()
        self._update_pattern()

    def _populate_ui(self):
        """Create the UI components"""
        _, QtCore, QtGui, QtWidgets = import_qt()

        # Main layout
        main_layout = QtWidgets.QVBoxLayout(self.widget)

        # Create splitter for top (table) and bottom (pattern) sections
        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        # Top section: Instruction table
        table_widget = self._create_instruction_table()
        splitter.addWidget(table_widget)

        # Bottom section: Pattern display
        pattern_widget = self._create_pattern_display()
        splitter.addWidget(pattern_widget)

        # Set initial splitter sizes (70% table, 30% pattern)
        splitter.setSizes([700, 300])

        main_layout.addWidget(splitter)

    def _create_instruction_table(self):
        """Create the instruction table widget"""
        _, QtCore, QtGui, QtWidgets = import_qt()

        container = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(container)

        # Toolbar with quick actions
        toolbar = QtWidgets.QHBoxLayout()

        self.btn_wildcard_mnemonics = QtWidgets.QPushButton("Mnemonics")
        self.btn_wildcard_mnemonics.clicked.connect(self._on_wildcard_all_mnemonics)
        toolbar.addWidget(self.btn_wildcard_mnemonics)

        self.btn_wildcard_registers = QtWidgets.QPushButton("Registers")
        self.btn_wildcard_registers.clicked.connect(self._on_wildcard_registers)
        toolbar.addWidget(self.btn_wildcard_registers)

        self.btn_wildcard_operands = QtWidgets.QPushButton("Operands")
        self.btn_wildcard_operands.clicked.connect(self._on_wildcard_all_operands)
        toolbar.addWidget(self.btn_wildcard_operands)

        self.btn_wildcard_memory = QtWidgets.QPushButton("Memory Operands")
        self.btn_wildcard_memory.clicked.connect(self._on_wildcard_memory_operands)
        toolbar.addWidget(self.btn_wildcard_memory)

        self.btn_wildcard_immutables = QtWidgets.QPushButton("Immutables")
        self.btn_wildcard_immutables.clicked.connect(self._on_wildcard_immutables)
        toolbar.addWidget(self.btn_wildcard_immutables)

        self.btn_wildcard_all = QtWidgets.QPushButton("All")
        self.btn_wildcard_all.clicked.connect(self._on_wildcard_all)
        toolbar.addWidget(self.btn_wildcard_all)

        self.btn_reset = QtWidgets.QPushButton("Reset")
        self.btn_reset.clicked.connect(self._on_reset_all)
        toolbar.addWidget(self.btn_reset)

        toolbar.addStretch()
        layout.addLayout(toolbar)

        # Create table
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Address",
            "Bytes",
            "Mnemonic",
            "Op1",
            "Op2",
            "Op3"
        ])

        # Disable cell selection - only our custom widgets handle clicks
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.table.setFocusPolicy(QtCore.Qt.NoFocus)

        # Populate table with instructions
        self.table.setRowCount(len(self.generator.instructions))

        for row_idx, insn in enumerate(self.generator.instructions):
            # Address column
            addr_item = QtWidgets.QTableWidgetItem(f"{insn.address:08X}")
            addr_item.setFlags(addr_item.flags() & ~QtCore.Qt.ItemIsEditable)
            self.table.setItem(row_idx, 0, addr_item)

            # Bytes column
            bytes_str = " ".join(f"{b:02X}" for b in insn.raw_bytes)
            bytes_item = QtWidgets.QTableWidgetItem(bytes_str)
            bytes_item.setFlags(bytes_item.flags() & ~QtCore.Qt.ItemIsEditable)
            self.table.setItem(row_idx, 1, bytes_item)

            # Mnemonic column with clickable label
            mnem_widget = QtWidgets.QWidget()
            mnem_widget.setStyleSheet("QWidget { background-color: transparent; }")
            mnem_layout = QtWidgets.QHBoxLayout(mnem_widget)
            mnem_layout.setContentsMargins(4, 2, 4, 2)
            mnem_label = QtWidgets.QLabel(insn.mnemonic)
            mnem_layout.addWidget(mnem_label)
            mnem_layout.addStretch()
            # Make entire cell clickable to toggle wildcard
            mnem_widget.mousePressEvent = lambda event, idx=row_idx: self._on_mnemonic_clicked(idx)
            mnem_widget.setCursor(QtCore.Qt.PointingHandCursor)
            self.table.setCellWidget(row_idx, 2, mnem_widget)
            self.mnemonic_widgets.append(mnem_widget)

            # Operand columns
            operand_row_widgets = []
            for op_idx in range(3):
                if op_idx < len(insn.operands):
                    op_widget = QtWidgets.QWidget()
                    op_widget.setStyleSheet("QWidget { background-color: transparent; }")
                    op_layout = QtWidgets.QHBoxLayout(op_widget)
                    op_layout.setContentsMargins(4, 2, 4, 2)
                    op_label = QtWidgets.QLabel(insn.operands[op_idx])
                    op_layout.addWidget(op_label)
                    op_layout.addStretch()
                    # Make entire cell clickable to toggle wildcard
                    op_widget.mousePressEvent = lambda event, i=row_idx, o=op_idx: self._on_operand_clicked(i, o)
                    op_widget.setCursor(QtCore.Qt.PointingHandCursor)
                    self.table.setCellWidget(row_idx, 3 + op_idx, op_widget)
                    operand_row_widgets.append(op_widget)
                else:
                    empty_item = QtWidgets.QTableWidgetItem("")
                    empty_item.setFlags(empty_item.flags() & ~QtCore.Qt.ItemIsEditable)
                    self.table.setItem(row_idx, 3 + op_idx, empty_item)
                    operand_row_widgets.append(None)
            self.operand_widgets.append(operand_row_widgets)

        # Resize columns to content
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setStretchLastSection(False)
        # Make table more compact
        self.table.verticalHeader().setDefaultSectionSize(20)  # Compact row height
        self.table.setShowGrid(True)

        layout.addWidget(self.table)
        return container

    def _create_pattern_display(self):
        """Create the pattern display widget"""
        _, QtCore, QtGui, QtWidgets = import_qt()

        container = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(container)

        # Statistics label (more compact)
        self.stats_label = QtWidgets.QLabel()
        font = self.stats_label.font()
        font.setPointSize(font.pointSize() - 1)  # Slightly smaller font
        self.stats_label.setFont(font)
        layout.addWidget(self.stats_label)

        # Pattern text area (more compact)
        self.pattern_text = QtWidgets.QTextEdit()
        self.pattern_text.setReadOnly(True)
        self.pattern_text.setMaximumHeight(80)  # Reduced from 100
        # Use monospace font (smaller)
        font = QtGui.QFont("Courier")
        font.setStyleHint(QtGui.QFont.Monospace)
        font.setPointSize(9)  # Slightly smaller
        self.pattern_text.setFont(font)
        layout.addWidget(self.pattern_text)

        # Buttons
        button_layout = QtWidgets.QHBoxLayout()

        self.btn_copy_pattern = QtWidgets.QPushButton("Copy")
        self.btn_copy_pattern.clicked.connect(self._on_copy_pattern)
        button_layout.addWidget(self.btn_copy_pattern)

        button_layout.addStretch()

        btn_close = QtWidgets.QPushButton("Close")
        btn_close.clicked.connect(self._on_close)
        button_layout.addWidget(btn_close)

        layout.addLayout(button_layout)
        return container

    def _update_pattern(self):
        """Update the pattern display with current wildcard settings"""
        if self.generator is None:
            return

        pattern = self.generator.to_yara_pattern()
        self.pattern_text.setPlainText(pattern)

        # Update statistics
        stats = self.generator.get_statistics()
        stats_text = (
            f"Total Nibbles: {stats['total_nibbles']} | "
            f"Fixed: {stats['fixed_nibbles']} | "
            f"Wildcarded: {stats['wildcarded_nibbles']} | "
            f"Specificity: {stats['specificity']:.1f}%"
        )
        self.stats_label.setText(stats_text)

    def _on_mnemonic_clicked(self, insn_index: int):
        """Handle mnemonic cell click - toggle wildcard state"""
        # Toggle the wildcard state
        current_state = self.generator.instructions[insn_index].wildcard_mnemonic
        self.generator.set_wildcard_mnemonic(insn_index, not current_state)
        # Update highlight
        self._update_cell_highlight(insn_index, -1)  # -1 for mnemonic
        self._update_pattern()

    def _on_operand_clicked(self, insn_index: int, op_index: int):
        """Handle operand cell click - toggle wildcard state"""
        # Toggle the wildcard state
        current_state = self.generator.instructions[insn_index].wildcard_operands[op_index]
        self.generator.set_wildcard_operand(insn_index, op_index, not current_state)
        # Update highlight
        self._update_cell_highlight(insn_index, op_index)
        self._update_pattern()

    def _update_cell_highlight(self, insn_index: int, op_index: int):
        """Update cell background color based on wildcard state"""
        _, QtCore, QtGui, _ = import_qt()

        # Use IDA's standard selection color from palette
        palette = self.table.palette()
        highlight_color = palette.highlight().color().name()

        if op_index == -1:
            # Mnemonic cell
            widget = self.mnemonic_widgets[insn_index]
            is_wildcarded = self.generator.instructions[insn_index].wildcard_mnemonic
            if is_wildcarded:
                widget.setStyleSheet(f"QWidget {{ background-color: {highlight_color}; }}")
            else:
                widget.setStyleSheet("QWidget { background-color: transparent; }")
        else:
            # Operand cell
            widget = self.operand_widgets[insn_index][op_index]
            if widget:
                is_wildcarded = self.generator.instructions[insn_index].wildcard_operands[op_index]
                if is_wildcarded:
                    widget.setStyleSheet(f"QWidget {{ background-color: {highlight_color}; }}")
                else:
                    widget.setStyleSheet("QWidget { background-color: transparent; }")

    def _flash_button(self, button):
        """Flash a button green to indicate action was performed"""
        _, QtCore, _, _ = import_qt()
        original_style = button.styleSheet()

        # Flash green
        button.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; }")

        # Revert after 500ms (shorter than copy button)
        QtCore.QTimer.singleShot(500, lambda: button.setStyleSheet(original_style))

    def _on_wildcard_all_mnemonics(self):
        """Wildcard all mnemonics"""
        self.generator.wildcard_all_mnemonics()
        self._refresh_checkboxes()
        self._update_pattern()
        self._flash_button(self.btn_wildcard_mnemonics)

    def _on_wildcard_registers(self):
        """Wildcard only register operands"""
        for insn in self.generator.instructions:
            for op_idx, op_type in enumerate(insn.operand_types):
                # Wildcard only register operands (o_reg)
                if op_type == ida_ua.o_reg:
                    if op_idx < len(insn.wildcard_operands):
                        insn.wildcard_operands[op_idx] = True
        self._refresh_checkboxes()
        self._update_pattern()
        self._flash_button(self.btn_wildcard_registers)

    def _on_wildcard_all_operands(self):
        """Wildcard all operands"""
        self.generator.wildcard_all_operands()
        self._refresh_checkboxes()
        self._update_pattern()
        self._flash_button(self.btn_wildcard_operands)

    def _on_wildcard_memory_operands(self):
        """Wildcard memory operands including call/jump targets"""
        for insn in self.generator.instructions:
            for op_idx, op_type in enumerate(insn.operand_types):
                # Wildcard all memory-related operand types:
                # o_mem: direct memory reference
                # o_displ: memory with displacement ([rbp-8])
                # o_phrase: memory phrase ([rax+rbx*4])
                # o_near: near addresses (call/jmp targets)
                # o_far: far addresses
                if op_type in (ida_ua.o_mem, ida_ua.o_displ, ida_ua.o_phrase,
                               ida_ua.o_near, ida_ua.o_far):
                    if op_idx < len(insn.wildcard_operands):
                        insn.wildcard_operands[op_idx] = True
        self._refresh_checkboxes()
        self._update_pattern()
        self._flash_button(self.btn_wildcard_memory)

    def _on_wildcard_immutables(self):
        """Wildcard only immediate values (constants)"""
        for insn in self.generator.instructions:
            for op_idx, op_type in enumerate(insn.operand_types):
                # Only wildcard immediate values (constants like 0x01, 42)
                # NOT memory addresses or other operand types
                if op_type == ida_ua.o_imm:
                    if op_idx < len(insn.wildcard_operands):
                        insn.wildcard_operands[op_idx] = True
        self._refresh_checkboxes()
        self._update_pattern()
        self._flash_button(self.btn_wildcard_immutables)

    def _on_wildcard_all(self):
        """Wildcard everything (mnemonics and all operands)"""
        self.generator.wildcard_all_mnemonics()
        self.generator.wildcard_all_operands()
        self._refresh_checkboxes()
        self._update_pattern()
        self._flash_button(self.btn_wildcard_all)

    def _on_reset_all(self):
        """Reset all wildcards"""
        self.generator.reset_wildcards()
        self._refresh_checkboxes()
        self._update_pattern()
        self._flash_button(self.btn_reset)

    def _refresh_checkboxes(self):
        """Refresh cell highlights based on wildcard state"""
        for row_idx, insn in enumerate(self.generator.instructions):
            # Update mnemonic highlight
            self._update_cell_highlight(row_idx, -1)

            # Update operand highlights
            for op_idx in range(len(insn.operands)):
                self._update_cell_highlight(row_idx, op_idx)

    def _on_copy_pattern(self):
        """Copy pattern to clipboard with visual feedback"""
        _, _, QtGui, QtWidgets = import_qt()
        pattern = self.generator.to_yara_pattern()
        QtWidgets.QApplication.clipboard().setText(pattern)
        ida_kernwin.msg("[*] Pattern copied to clipboard\n")

        # Visual feedback: temporarily change button appearance
        original_text = self.btn_copy_pattern.text()
        original_style = self.btn_copy_pattern.styleSheet()

        # Change to "Copied!" with green background
        self.btn_copy_pattern.setText("Copied!")
        self.btn_copy_pattern.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; }")

        # Create a timer to revert after 1 second
        _, QtCore, _, _ = import_qt()
        QtCore.QTimer.singleShot(1000, lambda: self._reset_copy_button(original_text, original_style))

    def _reset_copy_button(self, original_text, original_style):
        """Reset copy button to original state"""
        self.btn_copy_pattern.setText(original_text)
        self.btn_copy_pattern.setStyleSheet(original_style)

    def _on_close(self):
        """Close the widget"""
        # The parent form will handle cleanup
        pass


def show_yara_creator(start_ea: int = 0, end_ea: int = 0, controller=None):
    """
    Show the YARA pattern creator for the given address range

    Args:
        start_ea: Start address of selection (0 for empty/placeholder)
        end_ea: End address of selection (0 for empty/placeholder)
        controller: Optional PluginController reference for tracking form lifecycle

    Returns:
        YaraCreatorForm instance
    """
    form = YaraCreatorForm(start_ea, end_ea, controller)
    form.Show()
    return form
