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

class DatabaseExportOptionsDialog(QDialog):
    def __init__(self, parent=None):
        super(DatabaseExportOptionsDialog, self).__init__(parent)
        self.setWindowTitle('Database Export Options')
        self.setModal(True)

        layout = QVBoxLayout(self)

        self.gnn_input_dimensions_label = QLabel('GNN Input Dimensions')
        self.gnn_input_dimensions_input = QSpinBox()
        self.gnn_input_dimensions_input.setRange(4, 32)
        self.gnn_input_dimensions_input.setValue(8)
        layout.addWidget(self.gnn_input_dimensions_label)
        layout.addWidget(self.gnn_input_dimensions_input)

        self.gnn_hidden_dimensions_label = QLabel('GNN Hidden Dimensions')
        self.gnn_hidden_dimensions_input = QSpinBox()
        self.gnn_hidden_dimensions_input.setRange(8, 64)
        self.gnn_hidden_dimensions_input.setValue(16)
        layout.addWidget(self.gnn_hidden_dimensions_label)
        layout.addWidget(self.gnn_hidden_dimensions_input)

        self.gnn_output_dimensions_label = QLabel('GNN Output Dimensions')
        self.gnn_output_dimensions_input = QSpinBox()
        self.gnn_output_dimensions_input.setRange(4, 64)
        self.gnn_output_dimensions_input.setValue(8)
        layout.addWidget(self.gnn_output_dimensions_label)
        layout.addWidget(self.gnn_output_dimensions_input)

        self.knn_max_label = QLabel('KNN Max Results')
        self.knn_max_input = QSpinBox()
        self.knn_max_input.setRange(1, 32)
        self.knn_max_input.setValue(4)
        layout.addWidget(self.knn_max_label)
        layout.addWidget(self.knn_max_input)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

    def get_inputs(self):
        return (
            self.gnn_input_dimensions_input.value(),
            self.gnn_hidden_dimensions_input.value(),
            self.gnn_output_dimensions_input.value(),
            self.knn_max_input.value(),
        )
