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

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QDialogButtonBox, QHBoxLayout, QLabel, QSpacerItem, QSizePolicy
)

class OkayCancelDialog(QDialog):
    def __init__(self, title: str = 'Select an Option', okay_text="OK", cancel_text="Cancel", width=300, height=50, parent=None):
        super().__init__(parent)

        # Set dialog properties
        self.setWindowTitle(title)
        self.setModal(True)
        self.setFixedSize(width, height)

        # Main layout
        main_layout = QVBoxLayout(self)

        # Add vertical spacer for alignment
        main_layout.addSpacerItem(QSpacerItem(0, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Button box with OK and Cancel buttons
        self.button_box = QDialogButtonBox()
        self.ok_button = self.button_box.addButton(okay_text, QDialogButtonBox.AcceptRole)
        self.cancel_button = self.button_box.addButton(cancel_text, QDialogButtonBox.RejectRole)

        # Connect button signals
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

        # Horizontal layout for centering buttons
        button_layout = QHBoxLayout()
        button_layout.addSpacerItem(QSpacerItem(20, 0, QSizePolicy.Expanding, QSizePolicy.Minimum))
        button_layout.addWidget(self.button_box)
        button_layout.addSpacerItem(QSpacerItem(20, 0, QSizePolicy.Expanding, QSizePolicy.Minimum))

        # Add button layout to main layout
        main_layout.addLayout(button_layout)

        # Add another vertical spacer for alignment
        main_layout.addSpacerItem(QSpacerItem(0, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Set the final layout
        self.setLayout(main_layout)
