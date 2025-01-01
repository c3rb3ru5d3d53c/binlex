
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
