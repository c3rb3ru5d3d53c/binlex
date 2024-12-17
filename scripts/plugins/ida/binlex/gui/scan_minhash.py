
from PyQt5.QtCore import Qt, QBuffer, QTimer, QByteArray
from PyQt5.QtGui import QMovie
from PyQt5.QtWidgets import QLabel, QDialog, QVBoxLayout, QDialogButtonBox, QDoubleSpinBox, QSpinBox, QLineEdit

class ScanMinHashInputDialog(QDialog):
    def __init__(self, parent=None):
        super(ScanMinHashInputDialog, self).__init__(parent)
        self.setWindowTitle("Scan MinHash")
        self.setModal(True)

        layout = QVBoxLayout(self)

        self.minhash_label = QLabel("MinHash String:")
        self.minhash_input = QLineEdit()
        layout.addWidget(self.minhash_label)
        layout.addWidget(self.minhash_input)

        self.byte_count_label = QLabel("Number of Bytes to Scan:")
        self.byte_count_input = QSpinBox()
        self.byte_count_input.setRange(4, 1024)
        layout.addWidget(self.byte_count_label)
        layout.addWidget(self.byte_count_input)

        self.threshold_label = QLabel("MinHash Similarity Threshold (default: 0.75):")
        self.threshold_input = QDoubleSpinBox()
        self.threshold_input.setRange(0.0, 1.0)
        self.threshold_input.setSingleStep(0.01)
        self.threshold_input.setValue(0.75)
        layout.addWidget(self.threshold_label)
        layout.addWidget(self.threshold_input)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

    def get_inputs(self):
        return (
            self.minhash_input.text(),
            self.byte_count_input.value(),
            self.threshold_input.value()
        )