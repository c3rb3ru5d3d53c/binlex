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

from PyQt5.QtCore import Qt, QBuffer, QTimer, QByteArray
from PyQt5.QtGui import QMovie
from PyQt5.QtWidgets import QLabel, QDialog, QVBoxLayout, QDialogButtonBox, QDoubleSpinBox, QSpinBox, QLineEdit

class ScanTLSHInputDialog(QDialog):
    def __init__(self, parent=None):
        super(ScanTLSHInputDialog, self).__init__(parent)
        self.setWindowTitle("Scan TLSH")
        self.setModal(True)

        layout = QVBoxLayout(self)

        self.tlsh_label = QLabel("TLSH String:")
        self.tlsh_input = QLineEdit()
        layout.addWidget(self.tlsh_label)
        layout.addWidget(self.tlsh_input)

        self.byte_count_label = QLabel("Number of Bytes to Scan:")
        self.byte_count_input = QSpinBox()
        self.byte_count_input.setRange(50, 1024)
        layout.addWidget(self.byte_count_label)
        layout.addWidget(self.byte_count_input)

        self.threshold_label = QLabel("TLSH Similarity Threshold (default: 100):")
        self.threshold_input = QDoubleSpinBox()
        self.threshold_input.setRange(0.0, 512)
        self.threshold_input.setSingleStep(1.00)
        self.threshold_input.setValue(100)
        layout.addWidget(self.threshold_label)
        layout.addWidget(self.threshold_input)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

    def get_inputs(self):
        return (
            self.tlsh_input.text(),
            self.byte_count_input.value(),
            self.threshold_input.value()
        )