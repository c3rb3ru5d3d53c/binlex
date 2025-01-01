
from PyQt5.QtCore import Qt, QBuffer, QTimer, QByteArray
from PyQt5.QtGui import QMovie
from PyQt5.QtWidgets import QLabel, QDialog, QVBoxLayout, QDialogButtonBox, QDoubleSpinBox, QSpinBox, QLineEdit

class BinlexServerSettingsDialog(QDialog):
    def __init__(self, parent=None):
        super(BinlexServerSettingsDialog, self).__init__(parent)
        self.setWindowTitle('Binlex Server Settings')
        self.setModal(True)

        layout = QVBoxLayout(self)

        self.url_lable = QLabel('Server URL')
        self.url_input = QLineEdit()
        layout.addWidget(self.url_lable)
        layout.addWidget(self.url_input)

        self.api_key_label = QLabel('API Key')
        self.api_key_input = QLineEdit()
        layout.addWidget(self.api_key_label)
        layout.addWidget(self.api_key_input)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

    def get_inputs(self):
        return (
            self.url_input.text(),
            self.api_key_input.text(),
        )
