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

class BinlexServerSettingsDialog(QDialog):
    def __init__(self, databases: list = ['default', 'goodware', 'malware'], show_include_blocks: bool = True, parent=None):
        super(BinlexServerSettingsDialog, self).__init__(parent)
        self.setWindowTitle('Binlex Server Settings')
        self.setModal(True)
        self.setFixedWidth(500)

        layout = QVBoxLayout(self)

        url = IDA().get_registry_value('url')
        api_key = IDA().get_registry_value('api_key')

        try:
            if url is not None and api_key is not None:
                client = BLClient(url=url, api_key=api_key)
                status, response = client.databases()
                if status == 200: databases = response
        except:
            pass

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

        self.database_label = QLabel('Database')
        self.database_input = QComboBox()
        self.database_input.addItems(databases)
        self.database_input.setCurrentText('default')
        layout.addWidget(self.database_label)
        layout.addWidget(self.database_input)

        self.include_blocks = QCheckBox('Include Blocks')
        self.include_blocks.setChecked(False)
        if show_include_blocks: layout.addWidget(self.include_blocks)

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
            self.database_input.currentText(),
            self.include_blocks.isChecked(),
        )
