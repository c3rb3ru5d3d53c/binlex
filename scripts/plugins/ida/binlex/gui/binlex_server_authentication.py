from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QLabel,
    QDialog,
    QVBoxLayout,
    QDialogButtonBox,
    QLineEdit,
    QPushButton,
    QHBoxLayout,
    QComboBox,
    QCheckBox,
)
from lib import IDA
from lib import BLClient

class BinlexServerAuthenticationDialog(QDialog):
    def __init__(self, parent=None):
        super(BinlexServerAuthenticationDialog, self).__init__(parent)
        self.setWindowTitle('Binlex Server Settings')
        self.setModal(True)
        self.setFixedWidth(500)

        layout = QVBoxLayout(self)

        url = IDA().get_registry_value('url')
        api_key = IDA().get_registry_value('api_key')

        self.url_label = QLabel('Server URL')
        self.url_input = QLineEdit()
        if url is not None: self.url_input.setText(url)
        layout.addWidget(self.url_label)
        layout.addWidget(self.url_input)

        self.api_key_label = QLabel('API Key')
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.Password)
        if api_key is not None: self.api_key_input.setText(api_key)

        self.show_hide_button = QPushButton('Show')
        self.show_hide_button.setCheckable(True)
        self.show_hide_button.clicked.connect(self.toggle_api_key_visibility)

        api_key_layout = QHBoxLayout()
        api_key_layout.addWidget(self.api_key_input)
        api_key_layout.addWidget(self.show_hide_button)

        layout.addWidget(self.api_key_label)
        layout.addLayout(api_key_layout)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

    def toggle_api_key_visibility(self):
        if self.show_hide_button.isChecked():
            self.api_key_input.setEchoMode(QLineEdit.Normal)
            self.show_hide_button.setText('Hide')
        else:
            self.api_key_input.setEchoMode(QLineEdit.Password)
            self.show_hide_button.setText('Show')

    def get_inputs(self):
        return (
            self.url_input.text(),
            self.api_key_input.text(),
        )
