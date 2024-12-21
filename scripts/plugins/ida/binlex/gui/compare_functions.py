from PyQt5.QtCore import Qt, QBuffer, QTimer, QByteArray
from PyQt5.QtGui import QMovie
from PyQt5.QtWidgets import QLabel, QDialog, QVBoxLayout, QDialogButtonBox, QDoubleSpinBox, QSpinBox, QLineEdit

class CompareFunctionsDialog(QDialog):
    def __init__(self, parent=None):
        super(CompareFunctionsDialog, self).__init__(parent)
        self.setWindowTitle('Binlex Compare Functions')
        self.setModal(True)

        layout = QVBoxLayout(self)

        self.minhash_score_threshold_label = QLabel('MinHash Score Threshold')
        self.minhash_score_threshold = QDoubleSpinBox()
        self.minhash_score_threshold.setRange(0.0, 1.0)
        self.minhash_score_threshold.setSingleStep(0.01)
        self.minhash_score_threshold.setValue(0.25)
        layout.addWidget(self.minhash_score_threshold_label)
        layout.addWidget(self.minhash_score_threshold)

        self.mininum_size_label = QLabel('Mininum Size Threshold')
        self.mininum_size = QSpinBox()
        self.mininum_size.setRange(64, 2048)
        layout.addWidget(self.mininum_size_label)
        layout.addWidget(self.mininum_size)

        self.size_ratio_label = QLabel('Size Ratio Threshold')
        self.size_ratio = QDoubleSpinBox()
        self.size_ratio.setRange(0.0, 1.0)
        self.size_ratio.setSingleStep(0.01)
        self.size_ratio.setValue(0.75)
        layout.addWidget(self.size_ratio_label)
        layout.addWidget(self.size_ratio)

        self.chromosome_minhash_ratio_threshold_label = QLabel('Chromosome MinHash Ratio Threshold')
        self.chromosome_minhash_ratio_threshold = QDoubleSpinBox()
        self.chromosome_minhash_ratio_threshold.setRange(0.0, 1.0)
        self.chromosome_minhash_ratio_threshold.setSingleStep(0.01)
        self.chromosome_minhash_ratio_threshold.setValue(0.75)
        layout.addWidget(self.chromosome_minhash_ratio_threshold_label)
        layout.addWidget(self.chromosome_minhash_ratio_threshold)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

    def get_inputs(self):
        return (
            self.minhash_score_threshold.value(),
            self.mininum_size.value(),
            self.size_ratio.value(),
            self.chromosome_minhash_ratio_threshold.value(),
        )
